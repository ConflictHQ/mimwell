#!/usr/bin/env python3
"""Project initializer — the scaffolding front door (issue #20).

Scaffold a NEW engagement portal by COPYING this template into a fresh TARGET
directory and transforming the COPY. The template itself is never mutated.
The target must be separate from the source (not an ancestor or descendant), and
a nested target gets its own Git repository rather than using its parent workspace.

    python3 scripts/init.py <target-dir> \
        [--name "Acme Co"] [--domain acme.conflict.media] [--slug acme] \
        [--shortName ACME] [--store json|sqlite|both] [--features a,b] \
        [--purpose company|topic|personal|project] [--recipe example.company@1.3.0] \
        [--identity "Leo Mata <leo@example.test>"] [--dry-run] [--force]

`--purpose`/`--recipe` select a brain kind (issue #200): which recipe from
recipes/catalog.json derives the ontology overlays, the owning scope level and the
portal template. Neither flag is a store choice — every kind scaffolds to the
`files` cell (git); adopting a store is always a later, explicit cutover
(docs/design/adr-authority-per-brain-kind.md). Omitting both keeps today's
project/engagement composition byte-identical.

What it does (each step is previewed-only under --dry-run):
  1. COPY    template/ -> target (shutil.copytree), excluding build artifacts,
             caches, secrets, and local stores. A Git checkout copies only
             tracked source paths (including their working edits); archives
             without source tracking retain their files. Refuses a non-empty
             target unless --force. Source files are never removed.
  2. STAMP   the TARGET's client.config.json — the single config seam every
             script + the worker reads (config.py / config.js). Sets
             brain.name/shortName/purpose/owner (the owner seam, #206 canonical
             form) and client.slug/client.domain (deploy identity — the seam
             does not move these), re-derives branding labels/titles/greeting
             and the assistant identity/audience from name+domain, sets
             brain.store, flips features, and — only when --purpose/--recipe
             is given — resolves `profile` (base + overlays),
             `scope.level`/`scope.id` and `portal.template` from the selected
             recipe (recipes/catalog.json).
  3. RENAME  the worker identity in the TARGET copies only: wrangler.toml and
             package.json `name` -> "<slug>-portal" (the only two hardcoded
             spots; client.config.json is the seam for everything else).
  4. STRIP   example content to a clean empty-state in the TARGET, preserving
             structure + .gitkeep: empty the app/*.json fill-in arrays, empty the
             analysis/artifacts/catalog.json and delete the example artifact
             render, delete the specs/01-phase-one example tree, delete the
             example docs under knowledge/docs. Memory skeletons already ship as
             (fill in) stubs. A non-project purpose additionally drops the
             meeting-driven knowledge skeleton (session tags/recordings,
             docs/sessions, docs/agendas, the client-framed memory stub) in favor
             of a purpose-neutral one, and writes the selected overlay's fill-in
             artifacts the shipped template doesn't yet ship (OVERLAY_FILLIN_STUBS)
             so `make portal-verify` passes without hand-authoring them first. A
             non-project purpose also DELETES the engagement trackers
             (ENGAGEMENT_TRACKER_FILES) pinned only by profiles/engagement.json's
             kinds/generators — an unselected overlay never populates them, so an
             empty stub only pads the scaffold (#325).
  5. CI      the production workflow (.github/workflows/ci.yml) was copied in
             step 1 and is now live at the target root. No client values are
             baked into it; the per-engagement secret NAMES + domain are
             recorded in the deploy docs. Warns (non-fatal) if required GitHub
             secrets look unset.
  6. BUILD   run `make build` in the target so the generated artifacts match the
             stripped sources, then run `make test` so the scaffold is
             gates-green (build + portal-verify + test) out of the box. The
             committed golden is fixture-pinned and copied as-is. The suite is
             composition-independent (#319), so every purpose runs it.
  7. GIT     set per-repo LOCAL git identity from --identity (never global) and
             wire core.hooksPath -> .githooks.
  8. NEXT    print the next actions.

Idempotent: re-running on an already-stamped target re-stamps from args without
re-copying (unless --force re-copies from the template first).

Stdlib only; matches the neighboring scripts (from __future__ import annotations,
ROOT via parents[1], tolerant IO).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_NAME = "client.config.json"

# ---------------------------------------------------------------------------
# Purpose -> shipped recipe (#200). `--purpose` is a shorthand for the matching
# `example.*` recipe in recipes/catalog.json; `--recipe <id>@<version>` selects
# any catalog recipe directly (a candidate, or an instance's own catalog entry).
# "project" is the legacy default composition (core + engagement + data at
# project scope) and is therefore a documented no-op: passing it explicitly
# leaves client.config.json untouched, same as passing neither flag.
# ---------------------------------------------------------------------------
PURPOSE_RECIPES: dict[str, tuple[str, str]] = {
    "company": ("example.company", "1.3.0"),
    "topic": ("example.topic", "1.1.0"),
    "personal": ("example.personal", "1.0.0"),
    "project": ("example.project", "1.2.3"),
}

# Knowledge paths that assume a meeting-driven consultancy engagement (session
# recordings, agendas, a client-framed context stub). Dropped for any resolved
# purpose other than "project" (#200 acceptance item 5).
MEETING_DRIVEN_KNOWLEDGE = (
    "knowledge/session-tags.json",
    "knowledge/session-recordings.json",
    "knowledge/docs/sessions",
    "knowledge/docs/agendas",
)

# app/*.json engagement trackers (#325): declared as kind artifacts or generator
# outputs by profiles/engagement.json ONLY (checked against every other
# profiles/*.json — none of company/topic/personal/data/documents/core pins
# these paths). A composition that does not select the "engagement" overlay
# never compiles or populates them (compose-schema.py drops their kinds,
# build_plan.py drops their `make` targets), so shipping them as empty stubs
# only pads the scaffold — and two of them (build-readiness, action-items) are
# fetched unconditionally by the two always-checked pages
# (index.html/app/session.html), which check-portal-links.py now treats as
# optional for the same reason. Kept byte-identical for the legacy
# project/engagement composition (composition is None) and for any recipe that
# does select "engagement" (e.g. --purpose project resolved explicitly).
ENGAGEMENT_TRACKER_FILES = (
    "app/raid.json",
    "app/roadmap.json",
    "app/user-stories.json",
    "app/action-items.json",
    "app/deliverables.json",
    "app/dependencies.json",
    "app/build-readiness.json",
)

SUBJECT_MD_TEMPLATE = """---
title: Subject Context
description: What this brain is about, who owns it, and the scope it sits at. (Replace this description with the real one-line summary.)
metadata:
  type: reference
---

# Subject Context

> Placeholder. Replace with the real subject context. Keep it to a screenful.

**[Subject Name]** is _(fill in: one sentence on what this brain is about — a
company, a topic, a person's own notes)_. **[Owner]** is _(fill in: who is
accountable for this brain's canon — docs/patterns/brain-scope.md)_.

## Scope

_(fill in: the scope address this brain sits at — e.g. `company:acme` — and its
parent, if any.)_

## What this brain tracks

_(fill in: one bullet per thing this brain exists to know. Keep each to a
sentence.)_

- _(fill in)_
"""

# Fill-in artifacts an overlay's kinds declare (profiles/<overlay>.json `kinds[].artifact`)
# that profiles/company.json and profiles/topic.json ship without a matching file under
# app/ — a gap #205 left open and #200's own verification (`make portal-verify` on a
# --purpose company/topic scaffold) runs into directly via check-brain-schema.py's
# "declared artifacts are files that exist" check. Written into the TARGET only, when
# the resolved composition selects that overlay, so the default project/engagement
# path (and the template itself) is untouched. filename -> (array key, one-line kind
# description); content mirrors the shipped app/*.json fill-in convention.
OVERLAY_FILLIN_STUBS: dict[str, dict[str, tuple[str, str]]] = {
    "company": {
        "functions.json": ("functions", "Business-function register: an organizational function that owns roles, policies and budgets."),
        "policies.json": ("policies", "Policy register: a company rule with an owner and an effective date. A change is a new policy that supersedes the old one, not an edit."),
        "roles.json": ("roles", "Role register: a named position with decision authority inside a business function. Not the estimation staffing file (specs/roles.json)."),
        "initiatives.json": ("initiatives", "Initiative register: a company-level effort with a sponsor, a desired change and measures; may span projects and functions."),
        "accounts.json": ("accounts", "Account register: a commercial relationship this company holds with another organization (customer, partner, vendor)."),
    },
    "topic": {
        "research-sources.json": ("sources", "Research-source register: a source this topic brain draws on."),
        "claims.json": ("claims", "Claim register: a specific, sourced assertion this topic brain has established."),
        "reading-sessions.json": ("sessions", "Reading-session register: a bounded pass over sources that produced claims or syntheses."),
        "open-threads.json": ("threads", "Open-thread register: a question this topic brain has not yet resolved."),
    },
}

# Same gap as OVERLAY_FILLIN_STUBS, for a kind that declares `storage` (a markdown
# source directory) instead of `artifact`: profiles/topic.json's `synthesis` kind
# points at knowledge/syntheses, which the shipped template doesn't create.
OVERLAY_STORAGE_DIRS: dict[str, tuple[str, ...]] = {
    "topic": ("knowledge/syntheses",),
}


def write_overlay_fillins(target: Path, composition: dict | None) -> None:
    if composition is None:
        return
    written = []
    for overlay in composition["overlays"]:
        for fname, (array_key, description) in OVERLAY_FILLIN_STUBS.get(overlay, {}).items():
            fpath = target / "app" / fname
            if fpath.exists():
                continue  # never overwrite content the shipped template already has.
            _dump_json(fpath, {
                "$comment": f"{description} Declared as a fill-in kind (source: fill-in, node: null) by "
                            f"profiles/{overlay}.json: not yet compiled into the brain by a gen-brain.py "
                            "adapter. Empty until this brain records entries.",
                array_key: [],
            })
            written.append(fname)
        for rel in OVERLAY_STORAGE_DIRS.get(overlay, ()):
            d = target / rel
            if d.is_dir():
                continue
            d.mkdir(parents=True, exist_ok=True)
            (d / ".gitkeep").touch()
            written.append(f"{rel}/")
    if written:
        _say(f"  overlay fill-ins: wrote {', '.join(sorted(written))} (declared by the selected overlay(s), missing from the shipped template)")


# ---------------------------------------------------------------------------
# Copy exclusions — build artifacts, caches, secrets, and the local SQLite
# store. These either regenerate (artifacts), are environment-local (secrets,
# caches), or are gitignored; none belong in a fresh scaffold.
# ---------------------------------------------------------------------------
EXCLUDE_DIRS = {
    "_site",
    "node_modules",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".wrangler",
}
# Exact-name files to drop, and a glob-ish prefix set for the brain DB family.
EXCLUDE_FILES = {".dev.vars", ".brain-sync.stamp", ":memory:"}
EXCLUDE_FILE_PREFIXES = ("brain.db",)  # brain.db, brain.db-wal, brain.db-shm

# ---------------------------------------------------------------------------
# Empty-state stripping plan.
#
# app/*.json fill-in files keep their documented structure ($comment, legends,
# titles) but their content arrays are emptied and any `count` is reset to 0.
# Each entry: filename -> tuple of array keys to set to [].
# ---------------------------------------------------------------------------
APP_JSON_ARRAYS: dict[str, tuple[str, ...]] = {
    "collections.json": ("collections",),
    "roadmap.json": ("tracks",),
    "deliverables.json": ("deliverables",),
    "user-stories.json": ("stories",),
    "stakeholders.json": ("people",),
    "glossary.json": ("terms",),
    "raid.json": ("items",),
    "deck.json": ("slides",),
    "decisions.json": ("decisions",),
    "open-questions.json": ("questions",),
    "action-items.json": ("items",),
    "sessions.json": ("sessions",),
}

# Example content deleted wholesale (relative to target root).
STRIP_DELETE_DIRS = ("specs/01-phase-one",)
STRIP_DELETE_FILES = (
    "knowledge/docs/roadmap-template.md",
    "knowledge/docs/action-items.md",
)

REQUIRED_FIELDS = ("name", "slug", "domain")

# Per-engagement secrets the production CI/deploy expects (NAMES only — never
# values). Used for the non-fatal pre-deploy warning + the deploy-doc record.
REQUIRED_SECRETS = ("ANTHROPIC_API_KEY", "CLOUDFLARE_API_TOKEN")
OPTIONAL_SECRETS = ("LINEAR_API_KEY", "JIRA_TOKEN", "FOSSIL_TOKEN")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _say(msg: str) -> None:
    print(msg, flush=True)


def _slugify(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in text.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")


def _parse_identity(identity: str) -> tuple[str, str]:
    """Split 'Name <email>' into (name, email). Tolerates a bare name or a
    bare email; missing halves come back empty."""
    identity = identity.strip()
    if "<" in identity and ">" in identity:
        name = identity[: identity.index("<")].strip()
        email = identity[identity.index("<") + 1 : identity.index(">")].strip()
        return name, email
    if "@" in identity:
        return "", identity
    return identity, ""


def _is_nonempty_dir(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir())


def validate_target(target: Path) -> Path:
    """Check both copy and restamp paths before any target mutation."""
    if target.is_symlink():
        raise SystemExit("ERROR: target must not be a symlink.")
    target = target.resolve()
    source = ROOT.resolve()
    if target == source or source in target.parents or target in source.parents:
        raise SystemExit("ERROR: target must be separate from the template (not itself, an ancestor or a descendant).")
    if target.exists() and not target.is_dir():
        raise SystemExit("ERROR: target must be a directory.")
    return target


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump_json(path: Path, data: dict) -> None:
    """Write JSON matching the repo style: 2-space indent, trailing newline,
    non-ASCII preserved (the configs carry em-dashes)."""
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Step 1 — copy
# ---------------------------------------------------------------------------
def _tracked_source_paths() -> set[Path] | None:
    """Index membership is the checkout boundary, not a snapshot of its bytes.

    Release archives also work without Git, including when extracted under an
    unrelated repository. Only use its index when the initializer itself is
    tracked. Never stage, clean, or otherwise mutate the source checkout.
    """
    if not _git_available():
        return None
    if _git(ROOT, 'rev-parse', '--show-toplevel', check=False).returncode:
        return None
    tracked = _git(ROOT, 'ls-files', '-z').stdout.split('\0')
    if 'scripts/init.py' not in tracked:
        return None
    paths = {Path(name) for name in tracked if name}
    return paths | {parent for path in paths for parent in path.parents}


def _copy_ignore(dir_path: str, names: list[str], *, source_paths: set[Path] | None = None) -> set[str]:
    """shutil.copytree ignore callback: drop excluded dirs/files anywhere in
    the tree, plus the brain DB family by prefix in app/."""
    ignored: set[str] = set()
    for name in names:
        full = Path(dir_path) / name
        if source_paths is not None and full.relative_to(ROOT) not in source_paths:
            ignored.add(name)
        elif full == ROOT / 'runtime/brain-classifier/target' or (name in EXCLUDE_DIRS and full.is_dir()):
            ignored.add(name)
        elif name in EXCLUDE_FILES:
            ignored.add(name)
        elif any(name.startswith(p) for p in EXCLUDE_FILE_PREFIXES) and full.is_file():
            ignored.add(name)
    return ignored


def copy_template(target: Path, *, force: bool) -> None:
    target = validate_target(target)
    if _is_nonempty_dir(target) and not force:
        raise SystemExit(
            f"ERROR: target {target} is non-empty. Re-run with --force to overwrite/re-copy."
        )
    source_paths = _tracked_source_paths()
    if target.exists() and force:
        shutil.rmtree(target)
    # An existing empty directory is a supported fresh target.
    shutil.copytree(ROOT, target, dirs_exist_ok=True,
                    ignore=lambda directory, names: _copy_ignore(directory, names, source_paths=source_paths))
    _say(f"  copied template -> {target}")


# ---------------------------------------------------------------------------
# Purpose/recipe resolution (#200) — reuses the engine's own recipe resolver
# (scripts/brain_recipes.py) against recipes/catalog.json so init derives the
# same ontology composition brain-recipes.py would report for that recipe,
# instead of hand-maintaining a second copy of the inheritance/versioning rules.
# ---------------------------------------------------------------------------
def _load_recipe_catalog():
    catalog_path = ROOT / "recipes" / "catalog.json"
    if not catalog_path.is_file():
        raise SystemExit(
            "ERROR: this edition does not include purpose/recipe selection. "
            "Run the default scaffold without --purpose or --recipe, or use an edition that ships recipes/catalog.json."
        )
    spec = importlib.util.spec_from_file_location("brain_recipes", ROOT / "scripts" / "brain_recipes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    catalog_doc = _load_json(catalog_path)
    return module, module.Catalog([catalog_doc], engine_root=ROOT)


def portal_template_for_scope(scope_level: str, overlays: list[str]) -> str:
    """Presentation default only; selecting it grants no pages or permissions."""
    if scope_level == "project":
        return "engagement"
    elif scope_level == "person":
        return "personal"
    elif scope_level == "company":
        return "company"
    elif scope_level == "workspace" and "topic" in overlays:
        return "topic"
    return "wiki"


def resolve_composition(opts: argparse.Namespace) -> dict | None:
    """--purpose/--recipe -> {base, overlays, scope_level, portal_template,
    recipe_id, recipe_version}, or None for the legacy default (leave
    client.config.json's profile/scope/portal untouched — the byte-identical
    project/engagement path). Never touches disk; resolution only."""
    if opts.purpose and opts.recipe:
        raise SystemExit("ERROR: pass --purpose or --recipe, not both.")
    if not opts.purpose and not opts.recipe:
        return None

    if opts.recipe:
        if "@" not in opts.recipe:
            raise SystemExit("ERROR: --recipe must be '<id>@<version>' (e.g. example.company@1.3.0).")
        recipe_id, _, recipe_version = opts.recipe.partition("@")
    else:
        if opts.purpose == "project":
            return None  # documented no-op: same bytes as the default.
        if opts.purpose not in PURPOSE_RECIPES:
            raise SystemExit(
                f"ERROR: unknown --purpose {opts.purpose!r}. Supported: {', '.join(PURPOSE_RECIPES)} "
                "(or pass --recipe <id>@<version> for any other recipes/catalog.json entry)."
            )
        recipe_id, recipe_version = PURPOSE_RECIPES[opts.purpose]

    module, catalog = _load_recipe_catalog()
    try:
        resolved, _bindings = catalog.resolve({"id": recipe_id, "version": recipe_version})
    except module.RecipeError as exc:
        raise SystemExit(f"ERROR: recipe resolution failed for {recipe_id}@{recipe_version}: {exc}") from exc

    layers = resolved["ontologyLayers"]
    bases = [layer["id"] for layer in layers if layer["role"] == "base"]
    if len(bases) != 1:
        raise SystemExit(f"ERROR: recipe {recipe_id}@{recipe_version} does not declare exactly one ontology base.")
    overlays = [layer["id"] for layer in layers if layer["role"] == "overlay"]
    scope_level = resolved["scope"]["level"]
    portal_template = portal_template_for_scope(scope_level, overlays)
    return {
        "base": bases[0],
        "overlays": overlays,
        "scope_level": scope_level,
        "portal_template": portal_template,
        "recipe_id": recipe_id,
        "recipe_version": recipe_version,
    }


# ---------------------------------------------------------------------------
# Step 2 — stamp client.config.json (the single seam)
# ---------------------------------------------------------------------------
def stamp_config(target: Path, opts: argparse.Namespace, composition: dict | None) -> None:
    cfg_path = target / CONFIG_NAME
    cfg = _load_json(cfg_path)

    name = opts.name
    short = opts.shortName or _slugify(name).replace("-", " ").upper().replace(" ", "")
    slug = opts.slug or _slugify(name)
    domain = opts.domain
    scope_level = composition["scope_level"] if composition else cfg.get("scope", {}).get("level", "project")
    default_purpose = f"{name} Project"
    if composition and scope_level != "project":
        label = {"company": "Company", "topic": "Topic", "personal": "Personal"}.get(
            composition["portal_template"], scope_level.title())
        default_purpose = f"{name} {label} Brain"
    purpose = opts.engagement or default_purpose

    # Owner seam (#206, Phase 2: canonical). brain.name/shortName/purpose/owner
    # are the documented form; a NEW scaffold is stamped there directly rather
    # than through the deprecated client.* alias (scripts/config.py / config.js
    # still resolve client.* for an EXISTING, unmigrated config, but a fresh
    # one has no reason to carry the deprecated fields). client.slug /
    # client.domain are deploy identity, not the owner seam, and stay here.
    brain = cfg.setdefault("brain", {})
    brain["name"] = name
    brain["shortName"] = short
    brain["purpose"] = purpose
    # Owner kind (owner review on #206): a brain scoped to a person
    # (`--purpose personal`, or any --recipe resolving to the person scope
    # level — #200's example.personal) is owned by a person, not an
    # organization pretending to be one. Every other composition, including
    # the default project/engagement path, keeps the organization default.
    owner_kind = "person" if composition and composition["scope_level"] == "person" else "organization"
    brain["owner"] = {"kind": owner_kind, "name": name}

    client = cfg.setdefault("client", {})
    client.pop("name", None)
    client.pop("shortName", None)
    client.pop("engagement", None)
    client["slug"] = slug
    client["domain"] = domain

    # Branding labels/titles/greeting derive from the name; colors/fonts stay.
    branding = cfg.setdefault("branding", {})
    branding["headerLabel"] = short
    branding["headerSub"] = "knowledge base agent"
    # Portal title, chat greeting/placeholder and assistant identity/audience
    # come from the selected portal template's assistantCopy (#206/#200), so a
    # company, topic or personal brain does not ship engagement wording. The
    # historical engagement template ID now supplies project presentation copy.
    scope_level = composition["scope_level"] if composition else cfg.get("scope", {}).get("level", "project")
    overlays = composition["overlays"] if composition else cfg.get("profile", {}).get("overlays", [])
    template_id = composition["portal_template"] if composition else cfg.get("portal", {}).get("template", "auto")
    if template_id == "auto":
        template_id = portal_template_for_scope(scope_level, overlays)
    templates = _load_json(target / "app" / "portal-templates.json")["templates"]
    copies = {t["id"]: t["assistantCopy"] for t in templates if t.get("assistantCopy")}
    # The catalog is instance-owned: an adopted catalog may predate purpose
    # homes. Preserve it and use its existing copy until the owner merges them.
    fallback = "engagement" if scope_level == "project" else "wiki"
    copy = copies.get(template_id) or copies.get(fallback) or copies.get("wiki") or copies.get("engagement")
    if copy is None:
        raise SystemExit("ERROR: portal-templates.json has no compatible assistantCopy; merge the template catalog before initializing.")
    fill = {"name": name, "domain": domain, "scope": scope_level}
    branding["portalTitle"] = copy["portalTitle"].format(**fill)
    branding["kgViewerTitle"] = f"{name} — Knowledge Graph"
    branding["greeting"] = copy["greeting"].format(**fill)
    branding["inputPlaceholder"] = copy["inputPlaceholder"].format(**fill)

    assistant = cfg.setdefault("assistant", {})
    assistant["identity"] = copy["identity"].format(**fill)
    assistant["audience"] = copy["audience"].format(**fill)

    # brain.store
    brain["store"] = opts.store

    # Feature flips: --features is a comma list of flags to turn ON; everything
    # else keeps the template default.
    if opts.features:
        features = cfg.setdefault("features", {})
        wanted = {f.strip() for f in opts.features.split(",") if f.strip()}
        unknown = wanted - {k for k in features if not k.startswith("$")}
        if unknown:
            _say(f"  WARNING: unknown feature flag(s) ignored: {', '.join(sorted(unknown))}")
        for flag in wanted - unknown:
            features[flag] = True

    # Purpose/recipe composition (#200): only touched when --purpose/--recipe is
    # given; otherwise profile/scope/portal stay exactly as the template ships
    # (core + engagement + data at project scope), so a plain --engagement/no-flag
    # run is byte-identical to before this flag existed.
    if composition is not None:
        profile = cfg.setdefault("profile", {})
        profile["base"] = composition["base"]
        profile["overlays"] = composition["overlays"]
        scope = cfg.setdefault("scope", {})
        scope["level"] = composition["scope_level"]
        scope["id"] = slug
        cfg.setdefault("portal", {})["template"] = composition["portal_template"]
        _say(
            f"  composition: recipe={composition['recipe_id']}@{composition['recipe_version']} "
            f"profile={profile['base']}+{profile['overlays']} scope={scope['level']}:{slug} "
            f"portal.template={composition['portal_template']}"
        )

    _dump_json(cfg_path, cfg)
    _say(f"  stamped {CONFIG_NAME}: brain={name!r} slug={slug!r} domain={domain!r} store={opts.store}")


# ---------------------------------------------------------------------------
# Step 3 — rename worker identity (wrangler.toml + package.json)
# ---------------------------------------------------------------------------
def rename_worker(target: Path, slug: str) -> None:
    worker_name = f"{slug}-portal"

    wrangler = target / "wrangler.toml"
    text = wrangler.read_text(encoding="utf-8")
    out_lines = []
    renamed = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("name ") and "=" in stripped and not renamed:
            indent = line[: len(line) - len(stripped)]
            out_lines.append(f'{indent}name = "{worker_name}"')
            renamed = True
        else:
            out_lines.append(line)
    wrangler.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    pkg_path = target / "package.json"
    pkg = _load_json(pkg_path)
    pkg["name"] = worker_name
    _dump_json(pkg_path, pkg)

    _say(f"  worker identity -> {worker_name!r} (wrangler.toml, package.json)")


# ---------------------------------------------------------------------------
# Step 4 — strip example content to empty-state
# ---------------------------------------------------------------------------
def strip_examples(target: Path) -> None:
    # 4a. Empty app/*.json content arrays; reset any `count` to 0.
    app = target / "app"
    for fname, array_keys in APP_JSON_ARRAYS.items():
        fpath = app / fname
        if not fpath.exists():
            continue
        data = _load_json(fpath)
        for key in array_keys:
            if key in data:
                data[key] = []
        if "count" in data:
            data["count"] = 0
        _dump_json(fpath, data)

    # 4b. Delete the example specs tree (manifest rebuilds empty in step 6).
    for rel in STRIP_DELETE_DIRS:
        d = target / rel
        if d.is_dir():
            shutil.rmtree(d)

    # 4c. Delete the example knowledge/docs files (.gitkeep + README stay).
    for rel in STRIP_DELETE_FILES:
        f = target / rel
        if f.is_file():
            f.unlink()

    # 4d. Empty the artifact catalog and delete the example artifact render so
    # neither the template-author "Example Artifact" lands in the brain (gen-brain
    # projects catalog.json into Artifact/Catalog nodes) nor its index.html/data
    # JSON gets published into _site/. Mirrors the specs/01-phase-one handling.
    cat = target / "analysis" / "artifacts" / "catalog.json"
    if cat.exists():
        cdata = _load_json(cat)
        if "artifacts" in cdata:
            cdata["artifacts"] = []
        _dump_json(cat, cdata)
    shutil.rmtree(target / "analysis" / "artifacts" / "example", ignore_errors=True)

    _say(
        f"  stripped: emptied {len(APP_JSON_ARRAYS)} app/*.json fill-in file(s) + the artifact catalog, "
        f"deleted {len(STRIP_DELETE_DIRS)} example tree(s) + {len(STRIP_DELETE_FILES)} example doc(s) + the example artifact"
    )
    _say("  memory/*.md ship as (fill in) skeletons — left intact (structure + headings preserved)")


# ---------------------------------------------------------------------------
# Step 4e — knowledge skeleton per purpose (#200 acceptance item 5)
#
# The template's shipped knowledge/ assumes a meeting-driven consultancy
# engagement: session tags/recordings, agenda + session doc folders, and a
# client-framed memory stub. That skeleton is right for the default
# project/engagement composition (left untouched) and wrong for a company,
# topic or personal brain, which has no client and no meetings to log.
# ---------------------------------------------------------------------------
def apply_knowledge_skeleton(target: Path, composition: dict | None) -> None:
    if composition is None:
        return  # project/engagement: today's meeting-driven skeleton, unchanged.

    dropped = []
    for rel in MEETING_DRIVEN_KNOWLEDGE:
        p = target / rel
        if p.is_dir():
            shutil.rmtree(p)
            dropped.append(rel)
        elif p.is_file():
            p.unlink()
            dropped.append(rel)

    client_md = target / "knowledge" / "memory" / "client.md"
    if client_md.is_file():
        client_md.unlink()
        dropped.append("knowledge/memory/client.md")
        subject_md = target / "knowledge" / "memory" / "subject.md"
        subject_md.write_text(SUBJECT_MD_TEMPLATE, encoding="utf-8")

        index = target / "knowledge" / "memory" / "MEMORY.md"
        if index.is_file():
            text = index.read_text(encoding="utf-8")
            text = text.replace(
                "| [`client.md`](client.md) | reference | Who the client is, what's being built, the repo/property map. |",
                "| [`subject.md`](subject.md) | reference | What this brain is about, who owns it, the scope it sits at. |",
            )
            index.write_text(text, encoding="utf-8")

    _say(f"  knowledge skeleton: purpose={composition['recipe_id']} — dropped {', '.join(dropped)}; added knowledge/memory/subject.md")


# ---------------------------------------------------------------------------
# Step 4f — drop unpinned engagement trackers (#325 acceptance)
# ---------------------------------------------------------------------------
def drop_unpinned_engagement_trackers(target: Path, composition: dict | None) -> None:
    if composition is None or "engagement" in composition["overlays"]:
        return  # project/engagement composition: these trackers are pinned, keep them.

    dropped = []
    for rel in ENGAGEMENT_TRACKER_FILES:
        p = target / rel
        if p.is_file():
            p.unlink()
            dropped.append(rel)
    if dropped:
        _say(f"  engagement trackers: purpose={composition['recipe_id']} — dropped {', '.join(dropped)} (unpinned outside the engagement overlay)")


# ---------------------------------------------------------------------------
# Step 5 — activate CI (record secret names; warn on unset)
# ---------------------------------------------------------------------------
def activate_ci(target: Path, domain: str, *, in_git: bool) -> None:
    ci = target / ".github" / "workflows" / "ci.yml"
    if ci.exists():
        _say("  CI: .github/workflows/ci.yml is live at the target root (no client values baked in)")
    else:
        _say("  WARNING: .github/workflows/ci.yml not found in the target — CI will not run")
    _record_secrets_in_deploy_doc(target, domain)
    _warn_unset_secrets(target, in_git=in_git)


def _record_secrets_in_deploy_doc(target: Path, domain: str) -> None:
    """Record the per-engagement deploy facts (secret NAMES + domain) into a
    dedicated DEPLOY.md at the scaffold root. NAMES only — never values. The
    template ships no standalone deploy doc, so init writes one. Idempotent:
    the file is rewritten from the current domain each run."""
    doc = target / "DEPLOY.md"
    if not (ROOT / "recipes" / "catalog.json").is_file():
        doc.write_text(
            "# Deployment\n\n"
            "This public edition scaffolds and verifies a brain. Choose a hosting target, "
            "configure its deployment settings in `client.config.json`, and follow the "
            "container instructions in `runtime/portal-container/README.md` when using "
            "Astrolift. The shipped CI workflow runs `make verify`.\n\n"
            f"**Configured domain:** `{domain}`\n",
            encoding="utf-8",
        )
        _say(f"  recorded public deployment target in DEPLOY.md (domain={domain})")
        return
    required = "\n".join(f"- `{s}`" for s in REQUIRED_SECRETS)
    optional = "\n".join(f"- `{s}`" for s in OPTIONAL_SECRETS)
    doc.write_text(
        "# Deployment\n\n"
        "Per-engagement deploy facts, recorded by `scripts/init.py`. The CI workflow "
        "(`.github/workflows/ci.yml`) and the Cloudflare deploy read these GitHub "
        "Actions secrets at run time; this file records their NAMES only — never set "
        "secret values here or anywhere in the repo.\n\n"
        f"**Domain to route:** `{domain}`\n\n"
        "## Required secrets\n\n"
        "Set before the first deploy (`gh secret set <NAME>`, or repo Settings → "
        "Secrets and variables → Actions):\n\n"
        f"{required}\n\n"
        "## Optional secrets\n\n"
        "Only needed if the matching tracker/integration is enabled in "
        "`client.config.json`:\n\n"
        f"{optional}\n\n"
        "## Steps\n\n"
        f"1. Route `{domain}` to the worker (Cloudflare custom domain or zone route).\n"
        "2. Put the Anthropic key on the worker: `wrangler secret put ANTHROPIC_API_KEY`.\n"
        "3. Set the GitHub Actions secrets above for CI/deploy.\n"
        "4. `make build && make portal-verify && make test`, then `make deploy`.\n"
        "5. Put Cloudflare Access in front of the domain (auth is at the edge).\n",
        encoding="utf-8",
    )
    _say(f"  recorded per-engagement secret names + domain in DEPLOY.md (domain={domain})")


def _warn_unset_secrets(target: Path, *, in_git: bool) -> None:
    """Non-fatal: warn if the required GitHub secrets look unset. Uses `gh
    secret list` when a gh CLI + repo remote exist; otherwise a generic
    reminder. Never fails the run."""
    if not in_git or not (ROOT / "recipes" / "catalog.json").is_file():
        return
    try:
        proc = subprocess.run(
            ["gh", "secret", "list"],
            cwd=target,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        _say(
            "  NOTE: could not check GitHub secrets (gh CLI / remote not available). "
            f"Ensure these are set before deploy: {', '.join(REQUIRED_SECRETS)}"
        )
        return
    if proc.returncode != 0:
        _say(
            "  NOTE: no GitHub remote/secret access yet. Set before first deploy: "
            f"{', '.join(REQUIRED_SECRETS)}"
        )
        return
    present = {line.split()[0] for line in proc.stdout.splitlines() if line.strip()}
    missing = [s for s in REQUIRED_SECRETS if s not in present]
    if missing:
        _say(f"  WARNING: required GitHub secret(s) appear unset: {', '.join(missing)} (set before deploy)")
    else:
        _say("  OK: required GitHub secrets are present")


# ---------------------------------------------------------------------------
# Step 6 — rebuild generated artifacts
# ---------------------------------------------------------------------------
def rebuild(target: Path) -> None:
    _say("  running `make build` in the target …")
    proc = subprocess.run(
        ["make", "build"], cwd=target, capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"ERROR: `make build` failed in {target} (exit {proc.returncode}).")
    _say("  build OK — generated artifacts now match the stripped sources")


def run_tests(target: Path) -> None:
    """Run the scaffold's own `make test` so a broken scaffold fails at creation
    time rather than on the engagement's first CI run (.github/workflows/ci.yml
    runs `make test`). Hard-fails init if the gate is red."""
    _say("  running `make test` in the target …")
    proc = subprocess.run(["make", "test"], cwd=target, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"ERROR: `make test` failed in {target} (exit {proc.returncode}).")
    # CI relies on this test invocation. Show unittest's final counts without
    # repeating the suite or dumping successful fixture/debug output.
    summary = re.search(r"(?m)^Ran \d+ tests? in [^\n]+\n\nOK(?: \([^\n]*\))?$", proc.stderr)
    if summary:
        _say(summary.group())
    _say("  test OK — the scaffold's test gate is green")


# NOTE: there is deliberately no golden-refresh step here.
#
# An earlier version re-pointed tests/golden/brain.empty-state.json at the
# scaffold's stripped brain, because the golden test then built from the LIVE
# repo — so a scaffold whose sources differed from the template's failed it. The
# test has since been rebased onto a pinned source fixture
# (tests/golden/empty-state-sources): it now pins the GENERATOR's behavior over
# fixed inputs, independent of whatever content a repo holds. Overwriting the
# golden with the scaffold's brain therefore breaks it permanently — the golden
# would encode an empty graph while the fixture still builds a populated one,
# and every new engagement would start with a red `make test`. The golden is
# copied verbatim with the rest of tests/ and must stay that way.


# ---------------------------------------------------------------------------
# Step 7 — git: init the scaffold, set LOCAL identity, bootstrap commit, hooks.
#
# A scaffolded portal IS a git repo: `make build` runs gen-activity.py (git log)
# and the portal homepage reads the resulting activity feed, so the target must
# be a repo with at least one commit before the build. We git-init the fresh
# copy, set the LOCAL identity (never global), make a bootstrap commit so the
# activity feed has history, and only then wire core.hooksPath (so the
# brain-sync pre-commit hook does not fire on the bootstrap commit itself).
# ---------------------------------------------------------------------------
def _git(target: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=target, check=check, capture_output=True, text=True)


def _in_git_repo(target: Path) -> bool:
    try:
        proc = _git(target, "rev-parse", "--show-toplevel", check=False)
    except (FileNotFoundError, subprocess.SubprocessError):
        return False
    # A brain nested in a workspace needs its own repository. Merely being
    # inside a parent worktree must not redirect identity/add/commit to it.
    return proc.returncode == 0 and Path(proc.stdout.strip()).resolve() == target.resolve()


def _git_available() -> bool:
    return shutil.which("git") is not None


def git_init_and_identity(target: Path, identity: str) -> bool:
    """Init the repo (if needed) and set the LOCAL identity. Returns whether the
    target is a usable git repo afterwards."""
    if not _git_available():
        _say("  NOTE: git not found on PATH — skipping repo init, identity, hooks, and bootstrap commit.")
        return False

    if not _in_git_repo(target):
        _git(target, "init", "-q")
        _say("  git init (new repo)")

    name = email = ""
    if identity:
        name, email = _parse_identity(identity)
        if name:
            _git(target, "config", "--local", "user.name", name)
        if email:
            _git(target, "config", "--local", "user.email", email)
        _say(f"  git identity (LOCAL): {name or '(unset)'} <{email or '(unset)'}>")
    else:
        # Need *some* identity for the bootstrap commit; fall back to a neutral
        # placeholder the user is told to replace. Never touches global config.
        if not _git(target, "config", "--local", "user.name", check=False).stdout.strip():
            _git(target, "config", "--local", "user.name", "Portal Maintainer")
        if not _git(target, "config", "--local", "user.email", check=False).stdout.strip():
            _git(target, "config", "--local", "user.email", "maintainer@example.invalid")
        _say("  git identity (LOCAL): placeholder set — pass --identity or `git config --local` to replace")
    return True


BOOTSTRAP_MSG = "chore: initialize engagement portal from project-brain template"


def git_bootstrap_commit(target: Path) -> bool:
    """Make the initial commit so gen-activity.py (git log) has history at build
    time. Hooks are NOT wired yet, so this commit is clean and unmediated.
    Returns True if it created the bootstrap commit (so the post-build step
    knows it may fold the rebuilt artifacts into it via --amend)."""
    if _git(target, "rev-parse", "--verify", "HEAD", check=False).returncode == 0:
        _say("  git: repo already has commits — skipping bootstrap commit")
        return False
    _git(target, "add", "-A")
    _git(target, "commit", "-q", "--no-verify", "-m", BOOTSTRAP_MSG)
    _say("  git: bootstrap commit created")
    return True


def git_fold_build_into_bootstrap(target: Path) -> None:
    """Amend the bootstrap commit to include the post-build artifacts + DEPLOY.md
    so the committed tree matches disk and the drift gate (portal-generated-clean,
    which diffs generated files against HEAD) is green out of the box. Safe: this
    is the new repo's only, unpushed commit — an amend, not a history rewrite.
    gen-activity.py needed a commit to exist at build time; the activity feed is
    excluded from the drift gate, so the changed hash here is harmless."""
    if _git(target, "diff", "--quiet", "HEAD", "--", check=False).returncode == 0:
        # Nothing changed on disk relative to the bootstrap commit (rare).
        return
    _git(target, "add", "-A")
    _git(target, "commit", "-q", "--no-verify", "--amend", "-m", BOOTSTRAP_MSG)
    _say("  git: folded built artifacts into the bootstrap commit (drift-clean)")


def git_wire_hooks(target: Path) -> None:
    """Point git at the committed .githooks/ (brain-sync pre-commit). Done last
    so it never mediates the bootstrap commit."""
    hooks = target / ".githooks"
    if hooks.is_dir():
        _git(target, "config", "--local", "core.hooksPath", ".githooks")
        _say("  git core.hooksPath -> .githooks")
    else:
        _say("  git hooks: no .githooks directory in this edition; using Git defaults")


# ---------------------------------------------------------------------------
# Interactive prompting for unset required fields
# ---------------------------------------------------------------------------
def prompt_required(opts: argparse.Namespace) -> None:
    """Fill unset required fields by prompting. Only reached when interactive
    (a TTY) and not --dry-run; otherwise missing fields are a hard error so the
    script is scriptable."""
    if not opts.name:
        opts.name = input("Brain name: ").strip()
    if not opts.domain:
        default_domain = f"{_slugify(opts.name)}.conflict.media" if opts.name else ""
        suffix = f" [{default_domain}]" if default_domain else ""
        opts.domain = input(f"Portal domain{suffix}: ").strip() or default_domain
    if not opts.slug:
        default_slug = _slugify(opts.name) if opts.name else ""
        suffix = f" [{default_slug}]" if default_slug else ""
        opts.slug = input(f"Slug (worker name <slug>-portal){suffix}: ").strip() or default_slug


def ensure_required(opts: argparse.Namespace, *, interactive_ok: bool) -> None:
    missing = [f for f in REQUIRED_FIELDS if not getattr(opts, f)]
    if not missing:
        return
    if interactive_ok and sys.stdin.isatty():
        prompt_required(opts)
        missing = [f for f in REQUIRED_FIELDS if not getattr(opts, f)]
    if missing:
        raise SystemExit(
            "ERROR: missing required field(s): "
            + ", ".join(f"--{f}" for f in missing)
            + " (pass as flags, or run interactively without --dry-run)."
        )


# ---------------------------------------------------------------------------
# Dry-run plan
# ---------------------------------------------------------------------------
def print_plan(target: Path, opts: argparse.Namespace) -> None:
    slug = opts.slug or _slugify(opts.name) if opts.name else "(unset)"
    _say("DRY RUN — plan only; nothing is written.\n")
    exists = "exists (non-empty)" if _is_nonempty_dir(target) else "new/empty"
    _say(f"  target: {target}  [{exists}]")
    _say(f"  source: {ROOT}  (never mutated)\n")
    _say("  1. COPY  template -> target")
    _say(f"           excluding dirs {sorted(EXCLUDE_DIRS)}")
    _say(f"           excluding files {sorted(EXCLUDE_FILES)} + {EXCLUDE_FILE_PREFIXES[0]}*")
    if _is_nonempty_dir(target) and not opts.force:
        _say("           (target is non-empty — real run would REFUSE without --force)")
    _say(f"  2. STAMP {CONFIG_NAME}: name={opts.name!r} shortName={opts.shortName or '(derived)'!r} "
         f"slug={slug!r} domain={opts.domain!r} store={opts.store}")
    if opts.features:
        _say(f"           features ON: {opts.features}")
    composition = resolve_composition(opts)
    if composition is not None:
        _say(
            f"           composition: recipe={composition['recipe_id']}@{composition['recipe_version']} "
            f"profile={composition['base']}+{composition['overlays']} scope={composition['scope_level']}:{slug} "
            f"portal.template={composition['portal_template']}"
        )
    _say(f"  3. RENAME worker -> {slug}-portal (wrangler.toml, package.json)")
    _say(f"  4. STRIP  empty {len(APP_JSON_ARRAYS)} app/*.json arrays; "
         f"delete {list(STRIP_DELETE_DIRS)} + {list(STRIP_DELETE_FILES)}")
    if composition is not None:
        _say(f"           knowledge skeleton: drop {list(MEETING_DRIVEN_KNOWLEDGE)} + client.md -> subject.md")
    _say("  5. CI     ci.yml live at target root; record secret names + domain in deploy docs; warn if unset")
    _say("  6. BUILD  run `make build` in target (gates-green empty-state artifacts), then run")
    _say("            `make test` (fails the scaffold if the gate is red)")
    _say(f"  7. GIT    LOCAL identity from {opts.identity or '(none)'!r}; core.hooksPath -> .githooks")
    _say("  8. NEXT   print next actions")


# ---------------------------------------------------------------------------
# Next actions
# ---------------------------------------------------------------------------
def print_next_actions(target: Path, opts: argparse.Namespace) -> None:
    slug = opts.slug or _slugify(opts.name)
    if not (ROOT / "recipes" / "catalog.json").is_file():
        _say("\nPublic brain scaffold ready (git repo initialized, bootstrap commit made). Next:")
        _say(f"  1. cd {target}")
        _say("  2. Add the brain's knowledge and records under knowledge/ and app/.")
        _say("  3. Run `make verify` to rebuild and validate the public edition.")
        _say("  4. Configure deployment for your hosting target; Astrolift container details are in")
        _say("     runtime/portal-container/README.md. CI runs the shipped `make verify` target.")
        _say("  5. git add -A && git commit")
        return
    _say("\nScaffold ready (git repo initialized, bootstrap commit made). Next:")
    _say(f"  1. cd {target}")
    _say("  2. Fill app/*.json with the brain's real content — the brain/portal trackers")
    _say("     (decisions, open-questions, glossary, stakeholders, …) are driven by app/*.json.")
    _say("     memory/*.md compiles into Memory nodes and search context. Tracker records still")
    _say("     come from app/*.json, so populate the tracker files too, not memory/*.md alone.")
    _say("  3. make build && make portal-verify && make test   (regenerate + gate locally).")
    _say("  4. git add -A && git commit                (commit content + rebuilt artifacts).")
    _say(f"  5. Add the GitHub remote, then set secrets: {', '.join(REQUIRED_SECRETS)}  (see DEPLOY.md).")
    _say(f"  6. Route {opts.domain} to the worker, then `make deploy`  (worker: {slug}-portal).")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="init.py",
        description="Scaffold a new brain from this template (copies + transforms; never mutates the template).",
    )
    p.add_argument("target", type=Path, help="Target directory for the new brain (created/overwritten).")
    p.add_argument("--name", default="", help="Brain name (required).")
    p.add_argument("--domain", default="", help="Portal domain, e.g. acme.conflict.media (required).")
    p.add_argument("--slug", default="", help="Slug for the worker name <slug>-portal (default: slug of --name).")
    p.add_argument("--shortName", default="", help="Short uppercase label for the header (default: derived from --name).")
    p.add_argument("--engagement", default="", help="Purpose description (default: '<name> Project', or the selected brain kind).")
    p.add_argument("--store", default="json", choices=("json", "sqlite", "both"), help="brain.store backend (default: json).")
    p.add_argument(
        "--purpose",
        default="",
        choices=("", *PURPOSE_RECIPES),
        help=(
            "Brain kind: selects the matching recipe from recipes/catalog.json and derives "
            "profile (base + overlays), scope.level and portal.template from it. Default "
            "(unset): the project/engagement composition, unchanged. Mutually exclusive with --recipe."
        ),
    )
    p.add_argument(
        "--recipe",
        default="",
        help=(
            "Recipe '<id>@<version>' from recipes/catalog.json to derive the composition from "
            "directly (e.g. example.company@1.3.0) — for a recipe --purpose has no shorthand for. "
            "Mutually exclusive with --purpose."
        ),
    )
    p.add_argument("--features", default="", help="Comma-separated feature flags to turn ON (e.g. 'authoring,semantic_search').")
    p.add_argument("--identity", default="", help="Git identity for the new repo, 'Name <email>' (set LOCAL only).")
    p.add_argument("--dry-run", action="store_true", help="Print the plan and exit without writing anything.")
    p.add_argument("--force", action="store_true", help="Overwrite/re-copy a non-empty target.")
    p.add_argument(
        "--skip-tests",
        action="store_true",
        help=(
            "Skip running `make test` in the scaffolded target. Default is to run it, so a real "
            "engagement always gets the creation-time gate; CI passes this when the same commit's "
            "test suite already ran elsewhere on the identical, unmodified tests/ tree."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    opts = build_parser().parse_args(argv)
    target = validate_target(opts.target)

    # Derive shortName/slug eagerly so the plan + interactive defaults are honest.
    if opts.name and not opts.slug:
        opts.slug = _slugify(opts.name)

    if opts.dry_run:
        # Dry-run never prompts and never writes; required fields may be unset.
        print_plan(target, opts)
        return 0

    ensure_required(opts, interactive_ok=True)
    if not opts.slug:
        opts.slug = _slugify(opts.name)

    # Resolved once, before anything is written, so a bad --purpose/--recipe
    # fails fast rather than after copying (or --force-wiping) the target.
    composition = resolve_composition(opts)

    already_scaffolded = (target / CONFIG_NAME).exists()
    recopy = opts.force or not already_scaffolded

    _say(f"Initializing brain -> {target}\n")

    # Step 1 — copy (skipped when re-stamping an existing scaffold without --force).
    if recopy:
        copy_template(target, force=opts.force)
    else:
        _say(f"  re-stamping existing scaffold at {target} (no re-copy; pass --force to re-copy)")

    # Step 2 — stamp the config seam.
    stamp_config(target, opts, composition)

    # Step 3 — rename worker identity.
    rename_worker(target, opts.slug)

    # Step 4 — strip example content (only on a fresh copy; a re-stamp leaves
    # the engagement's real content alone).
    if recopy:
        strip_examples(target)
        apply_knowledge_skeleton(target, composition)
        write_overlay_fillins(target, composition)
        drop_unpinned_engagement_trackers(target, composition)

    # Step 7a — git init + LOCAL identity, then a bootstrap commit so the build's
    # gen-activity.py (git log) has history. Done before the build; hooks are
    # wired afterwards so the brain-sync pre-commit never mediates this commit.
    in_git = git_init_and_identity(target, opts.identity)
    bootstrapped = git_bootstrap_commit(target) if in_git else False

    # Step 5 — activate CI / record per-engagement secret names + domain / warn.
    activate_ci(target, opts.domain, in_git=in_git)

    # Step 6 — rebuild generated artifacts to match the stripped sources, then
    # prove the scaffold's own `make test` gate is green at creation, so a broken
    # scaffold fails loudly here rather than on the engagement's first CI run.
    # The committed golden is fixture-pinned and copied verbatim — never
    # rewritten from the scaffold's brain (see the note by strip_examples).
    rebuild(target)
    if opts.skip_tests:
        _say("  skipping `make test` in the target (--skip-tests): the caller vouches the same tests/ tree is already green")
    else:
        run_tests(target)

    # Fold the post-build artifacts + DEPLOY.md into the bootstrap commit so the
    # committed tree matches disk and the drift gate is green from the start.
    if bootstrapped:
        git_fold_build_into_bootstrap(target)

    # Step 7b — wire the committed pre-commit hook last (clean bootstrap commit).
    if in_git:
        git_wire_hooks(target)

    # Step 8 — next actions.
    print_next_actions(target, opts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
