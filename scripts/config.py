#!/usr/bin/env python3
"""Central config barrel — the single source of truth for the whole pipeline.

`client.config.json` is the one entry point for engagement configuration
(see docs/primitives/client-config.md). This module loads it ONCE on first
import, validates it (against schemas/client.config.schema.json when present),
resolves referenced-file paths to absolute, and exposes a cached, read-only
singleton:

    from config import settings

    settings.brain.store            # -> "json"
    settings.brain.name             # -> "Example Co" (or client.name, #206 alias)
    settings.brain.owner            # -> {"kind": "organization", "name": "Example Co"}
    settings.features.autosync      # -> True
    settings.estimation.bands       # -> absolute Path to specs/estimate-bands.json
    settings.knowledge.curation     # -> absolute Path to knowledge/curation.json
    settings.get("client", "name")  # -> "Example Co"

Design
------
- This barrel is the intended single source of truth; several scripts still read
  client.config.json directly and are pending migration (see the CONSUMERS list at
  the bottom of this file).
- The singleton is FROZEN after load: config is input, not mutable state.
  Reload only via reinit() in tests.
- Referenced-file POINTERS declared from the center are resolved to absolute
  Paths so consumers follow the pointer without knowing the layout:
  estimation.bands, estimation.roles, knowledge.curation, knowledge.enrichment,
  knowledge.recordings.
- Stdlib only (json / os / pathlib), matching the neighboring scripts.
- Validation against the JSON Schema is a clean no-op when jsonschema or the
  schema file is absent (the schema may not be present in a minimal install).
  When the schema IS present, an invalid config fails fast with a concise,
  sourced one-liner (not a raw jsonschema traceback).

Defaults
--------
Every getter returns a sane default when a key is missing, so a partial config
(or a brand-new engagement) still runs:
    brain.store           "json"
    brain.graduate_at_nodes 20000
    features.*            False, except autosync True
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "client.config.json"
SCHEMA_PATH = ROOT / "schemas" / "client.config.schema.json"

# Keys whose string value is a path to a referenced file, registered from the
# center. Resolved to absolute Paths on load: section -> [keys].
_POINTER_KEYS: dict[str, tuple[str, ...]] = {
    "estimation": ("bands", "roles"),
    "knowledge": ("curation", "enrichment", "recordings"),
}

# Conservative defaults for the small inline settings/flags.
_DEFAULTS: dict[str, Any] = {
    "authoring": {
        # Writable authoring layer (#38). Inert unless features.authoring is on.
        # storage_mode: json-commit (edit -> commit JSON via GitHub API), the
        # files-cell writer; a declared store authority has its own governed
        # writer and the Worker never writes it. editorial:
        # direct-to-branch or pr. bot is the commit identity (no AI attribution).
        # editor_role gates /api/edit when features.authoring_access_gate is on.
        "storage_mode": "json-commit",
        "editorial": "direct",
        "branch": "main",
        "bot": {"name": "", "email": ""},
        "editor_role": "",
    },
    "brain": {
        "store": "json",
        "graduate_at_nodes": 20000,
        "ci_sync": "enforce",
        "autosync_on": ("stop", "precommit"),
        # Where non-markdown artifacts live. `git` is correct until it is not;
        # lfs/s3/efs/external are the graduations. Blobs graduate INDEPENDENTLY
        # of the node store — a corpus of recordings outgrows git long before its
        # graph outgrows JSON. Reported in the manifest's substrate block.
        "blobs": "git",
        # Purpose-neutral owner seam (#206, Phase 2: canonical). _resolve_owner_seam
        # fills name/shortName/purpose/owner from client.* (a deprecated alias)
        # when the brain.* form is absent, so these defaults only answer for a
        # config with neither.
        "name": "",
        "shortName": "",
        "purpose": "",
        "owner": {"kind": "organization", "name": ""},
    },
    "scope": {
        # The scope spine. An instance that declares nothing is a project-scope
        # root named for its slug — which is exactly what a fresh engagement
        # portal is, so the default is the honest answer rather than a placeholder.
        # `parent`/`peers` are scope addresses (`<level>:<id>`).
        "level": "project",
        "id": "",
        "parent": None,
        "peers": (),
    },
    "profile": {
        # Ontology composition: base + ORDERED overlays. Empty overlays means
        # "fall back to brain-schema.json's legacy single-string `profile`", so an
        # instance that has not migrated still reports a composition and the skew
        # stays visible instead of absent.
        "base": "core",
        "overlays": (),
    },
    "federation": {
        # The publish-upward contract. Defaults are CLOSED: an instance that has
        # declared nothing publishes nothing. The failure mode being defended
        # against is a company brain quietly inhaling an engagement's confidential
        # fragments, so opening the boundary must be an explicit act.
        "publishes": (),
        "withholds": (),
        "children": (),
        # Signed consent to publish upward, one entry per parent (#213).
        "enrollments": (),
    },
    "portal": {
        # Presentation profile (W1.10): which portal template frames the brain.
        # Independent of `profile` (the ontology); a template orders and groups
        # registered pages and sets the front door, never invents a page.
        "template": "engagement",
    },
    "deploy": {
        # Where the brain runs and what persistence is attached there. The target
        # does not change what the brain IS (canon is git, every projection is
        # rebuildable) — it decides which projections are ALLOWED to exist.
        "target": "cloudflare-worker",
        "persistence": (),
        "replicas": None,
    },
    "semantic": {
        # Semantic/embedding retrieval (#27). The embedder is pluggable and
        # config-selected (mirrors recordings.diarization); empty module/class ->
        # the deterministic, stdlib-only local default (no API key). Gated by
        # features.semantic_search. No file pointers, so nothing in _POINTER_KEYS.
        "embedder": {
            "module": "",
            "class": "",
            "model": "",
            "apiKeyEnv": "",
            "dim": 1024,
        },
        # Vector substrate, graduating independently of brain.store: a small
        # corpus with heavy semantic search graduates vectors first.
        "substrate": "local",
    },
    "staleness": {
        # Staleness / review-cadence sweep (#29). Advisory report flagging brain
        # content that needs re-confirmation, computed by scripts/gen-staleness.py
        # from node `durability` + last-touched (git history of node.source).
        # Windows are in DAYS; a 0/absent window disables that check. Gated by
        # features.staleness. No file pointers (inline scalars, like brain.*), so
        # nothing in _POINTER_KEYS. The conservative defaults below keep the
        # empty-state report quiet.
        "point_in_time_window_days": 180,
        "open_question_window_days": 90,
        "decision_cadence_days": 365,
    },
    "features": {
        "authoring": False,
        "authoring_agent": False,
        "authoring_wysiwyg": False,
        "authoring_wysiwyg_agent": False,
        "authoring_access_gate": False,
        "brain_d1": False,
        "corpus_d1": False,
        "semantic_search": False,
        "observability": False,
        "staleness": False,
        "autosync": True,
    },
}


def _freeze(value: Any) -> Any:
    """Recursively make a JSON value read-only (dicts -> MappingProxyType,
    lists -> tuples). Paths and scalars pass through."""
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


class _Section:
    """Attribute + mapping view over one frozen config section, backed by
    defaults so missing keys still return a value."""

    def __init__(self, data: Any, defaults: dict[str, Any] | None = None):
        self._data = data if isinstance(data, MappingProxyType) else _freeze(data)
        self._defaults = defaults or {}

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        if name in self._defaults:
            return self._defaults[name]
        raise AttributeError(f"config section has no key {name!r}")

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)

    def get(self, name: str, default: Any = None) -> Any:
        if name in self._data:
            return self._data[name]
        return self._defaults.get(name, default)

    def __contains__(self, name: str) -> bool:
        return name in self._data or name in self._defaults

    def raw(self) -> Any:
        return self._data


class _Settings:
    """The frozen config singleton. Top-level sections are exposed as
    attributes (settings.brain, settings.features, ...); typed getters apply
    defaults so a partial config still runs."""

    def __init__(self, data: dict[str, Any]):
        self._data = _freeze(data)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._data:
            return _Section(self._data[name], _DEFAULTS.get(name))
        if name in _DEFAULTS:
            return _Section({}, _DEFAULTS[name])
        raise AttributeError(f"config has no section {name!r}")

    def get(self, *path: str, default: Any = None) -> Any:
        """Dotted-path getter: settings.get('client', 'name')."""
        cur: Any = self._data
        for key in path:
            if isinstance(cur, MappingProxyType) and key in cur:
                cur = cur[key]
            else:
                return default
        return cur

    def raw(self) -> Any:
        """The whole frozen config object (read-only)."""
        return self._data


def _resolve_owner_seam(data: dict[str, Any]) -> None:
    """Purpose-neutral owner seam (#206, Phase 2: canonical). `brain.name` /
    `brain.shortName` / `brain.purpose` / `brain.owner {kind, name}` are the
    documented, canonical seam; `client.name` / `client.shortName` /
    `client.engagement` are DEPRECATED read aliases, accepted for one more
    release (2026-09-24 decision), so an unmigrated config (or one with no
    `client` block at all) still resolves. Mutates `data["brain"]` IN PLACE,
    filling only the keys the config itself left absent — an explicit
    `brain.*` value is never overwritten. Runs after schema validation
    (validates the file as authored) and before freezing, so every reader —
    including a wholly missing `brain` section, via _DEFAULTS — sees the same
    resolved view through one accessor."""
    client = data.get("client")
    if not isinstance(client, dict):
        client = {}
    brain = data.get("brain")
    if not isinstance(brain, dict):
        brain = {}
        data["brain"] = brain
    if "name" not in brain and client.get("name"):
        brain["name"] = client["name"]
    if "shortName" not in brain:
        if client.get("shortName"):
            brain["shortName"] = client["shortName"]
        elif brain.get("name"):
            brain["shortName"] = brain["name"]
    if "purpose" not in brain and client.get("engagement"):
        brain["purpose"] = client["engagement"]
    if "owner" not in brain and client.get("name"):
        brain["owner"] = {"kind": "organization", "name": client["name"]}


def _resolve_pointers(data: dict[str, Any]) -> None:
    """Rewrite referenced-file pointer strings to absolute Paths, in place."""
    for section, keys in _POINTER_KEYS.items():
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for key in keys:
            val = block.get(key)
            if isinstance(val, str) and val:
                block[key] = (ROOT / val).resolve()


def _validate(data: dict[str, Any]) -> None:
    """Schema validation. A clean no-op when jsonschema or the schema file is
    absent (the schema may not be present in a minimal install). When the schema
    IS present and the config is INVALID, fail fast with a concise, sourced
    one-liner naming client.config.json and the offending key — not a raw
    jsonschema traceback surfaced through whichever unrelated script triggered
    the import."""
    if not SCHEMA_PATH.exists():
        return
    try:
        import jsonschema  # type: ignore
        from jsonschema import ValidationError  # type: ignore
    except ImportError:
        return
    schema = json.loads(SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(instance=data, schema=schema)
    except ValidationError as exc:
        key = ".".join(str(p) for p in exc.absolute_path) or "(root)"
        raise SystemExit(
            f"client.config.json is invalid at '{key}': {exc.message}\n"
            f"  (validated against {SCHEMA_PATH.name})"
        ) from None


def _load() -> _Settings:
    data = json.loads(CONFIG_PATH.read_text())
    _validate(data)
    _resolve_owner_seam(data)
    _resolve_pointers(data)
    return _Settings(data)


# Module-level singleton, loaded + validated + frozen exactly once on import.
settings = _load()


def reinit() -> _Settings:
    """Reload the config from disk and re-freeze. For TESTS ONLY — production
    code treats `settings` as immutable input."""
    global settings
    settings = _load()
    return settings


# Follow-on migration (#17 surface, separate change): point each of these at
# this barrel and delete its private `CONFIG = ROOT / 'client.config.json'`:
#   backfill-issues-history.py, build-kg.py, curate-kg.py, diarize-transcripts.py,
#   enrich-kg.py, fetch-drive-audio.py, gen-action-items.py, gen-activity.py,
#   gen-analyses.py, gen-assets.py, gen-dependencies.py, gen-docs-manifest.py,
#   gen-issues.py, gen-knowledge-pack.py, gen-sessions.py, gen-specs.py,
#   gen-transcripts.py, import-drive-docs.py, merge-kg.py, sync-tracker.py
# (gen-assets.py + gen-docs-manifest.py both read knowledge.sources raw via
# json.loads(CONFIG.read_text()); the coverage gate check-index-coverage.py reads
# the SAME sources through this barrel, so route them here to avoid drift.)
