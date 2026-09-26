#!/usr/bin/env python3
"""Resolve what `make build` produces from the brain's selected profile (#202).

Each profile layer (profiles/<name>.json) declares under `generators` the build
targets it requires, their drift-gated artifacts and the gen-brain.py adapters
its records feed. The brain selects layers in client.config.json#profile
(base + ordered overlays); this module unions their declarations, so a brain
without the engagement overlay runs no plan generators, gates no plan artifacts
and federates no plan sources.

A config that declares no overlays keeps a hand-maintained brain-schema.json and
says nothing about what it holds, so it builds the template's original
composition (LEGACY) unchanged.

    python3 scripts/build_plan.py targets     # ordered make targets
    python3 scripts/build_plan.py artifacts   # drift-gated outputs (GENERATED)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ("core", "engagement", "data")


def layers(root: Path = ROOT) -> list[str]:
    config = Path(root) / "client.config.json"
    profile = (json.loads(config.read_text(encoding="utf-8")) if config.is_file() else {}).get("profile") or {}
    overlays = list(profile.get("overlays") or ())
    return [profile.get("base", "core"), *overlays] if overlays else list(LEGACY)


def _declared() -> dict[str, dict]:
    """Every profile layer's `generators` declaration, by layer name. A layer
    without a file contributes nothing; compose-schema.py (the first build
    target) is what rejects an unknown overlay."""
    return {path.stem: json.loads(path.read_text(encoding="utf-8")).get("generators") or {}
            for path in sorted((ROOT / "profiles").glob("*.json"))}


def _declarations(root: Path) -> list[dict]:
    declared = _declared()
    return [declared[name] for name in layers(root) if name in declared]


def targets(root: Path = ROOT) -> list[str]:
    ordered = [(entry["stage"], i, j, entry["target"])
               for i, decl in enumerate(_declarations(root))
               for j, entry in enumerate(decl.get("make", []))]
    return [target for *_, target in sorted(ordered)]


def artifacts(root: Path = ROOT) -> list[str]:
    by_target = {entry["target"]: entry.get("artifacts", [])
                 for decl in _declarations(root) for entry in decl.get("make", [])}
    return [path for target in targets(root) for path in by_target[target]]


def skipped_adapters(root: Path = ROOT) -> set[str]:
    """gen-brain.py adapters a profile layer declares that the brain did not select."""
    declared = {name for decl in _declared().values() for name in decl.get("brain", [])}
    return declared - {name for decl in _declarations(root) for name in decl.get("brain", [])}


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) == 2 else ""
    if kind not in ("targets", "artifacts"):
        sys.exit("usage: build_plan.py targets|artifacts")
    print(" ".join(globals()[kind]()))
