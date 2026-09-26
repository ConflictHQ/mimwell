#!/usr/bin/env python3
"""Validate every committed source artifact against its JSON Schema in schemas/.

The single input-schema gate for the engagement. Schemas are the contract that
both humans AND agents author to, so malformed data fails fast with a clear
pointer instead of rendering broken in the portal. Run by `make portal-verify`
(#6) and CI (#7); this module only provides the check.

What it validates
-----------------
  app/decisions.json        -> schemas/decisions.schema.json
  app/open-questions.json   -> schemas/open-questions.schema.json
  app/action-items.json     -> schemas/action-items.schema.json
  app/raid.json             -> schemas/raid.schema.json
  app/roadmap.json          -> schemas/roadmap.schema.json
  app/deliverables.json     -> schemas/deliverables.schema.json
  app/user-stories.json     -> schemas/user-stories.schema.json
  app/stakeholders.json     -> schemas/stakeholders.schema.json
  app/glossary.json         -> schemas/glossary.schema.json
  app/sessions.json         -> schemas/sessions.schema.json
  app/assets.json           -> schemas/assets.schema.json
  app/docs-manifest.json    -> schemas/docs-manifest.schema.json
  app/knowledge_graph.json  -> schemas/knowledge-graph.schema.json (node/edge)
  app/sources.json          -> schemas/sources.schema.json (source inventory, #13)
  app/staleness.json        -> schemas/staleness.schema.json (staleness sweep, #29)
  app/machine.json          -> schemas/machine.schema.json (living blueprint, #69)
  analysis/artifacts/catalog.json -> schemas/artifact-catalog.schema.json (#14)
  client.config.json        -> schemas/client.config.schema.json
  specs/**/*.md frontmatter -> schemas/specs-frontmatter.schema.json
  app/brain.json            -> schemas/brain-envelope (when present; read-only
                               compiled envelope from gen-brain.py — validates the
                               optional meta{version,...} block plus the node/edge
                               arrays via brain-node/brain-edge $refs)

A missing artifact is skipped cleanly (a brand-new engagement may not have every
file yet); a missing schema is an error (the registry is part of the template).

Versioned data-file envelope (#57)
----------------------------------
The fill-in contract (bootstrap.md; the version/updated/changelog properties
already present in the schemas) says every hand edit to a portal-rendered data
file bumps `version`, refreshes `updated`, and appends a dated `changelog`
entry — so every edit is versioned and attributable. The schemas keep those
properties optional and loosely typed; this module adds the strict, stdlib
contract check on top for every whole-file artifact that has ADOPTED the
envelope:

  trigger — the artifact carries a `changelog` key, or both `version` and
            `updated` (the envelope travels as a set; a lone generated format
            `version` such as app/sources.json's, or a lone free-form `updated`
            label in a not-yet-versioned seed, does not opt a file in);
  checks  — version is a positive integer, updated is a real YYYY-MM-DD date,
            changelog is a non-empty list of {date: YYYY-MM-DD, note: str}.

Dependencies (declared in requirements.txt — #10): jsonschema, PyYAML.

Run from anywhere:  python3 scripts/validate-schemas.py
Exit code 0 = all valid, 1 = at least one failure (or a dependency missing).
"""
from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

from ontology import OntologyError, load_registry

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"

# YYYY-MM-DD shape gate; date.fromisoformat behind it rejects impossible dates.
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# artifact (repo-relative) -> schema filename. The whole-file artifacts.
ARTIFACTS: dict[str, str] = {
    "stores/examples/contract.json": "knowledge-store.schema.json",
    "practices/examples/policy.json": "knowledge-policy.schema.json",
    "app/evidence.json": "evidence.schema.json",
    "recipes/catalog.json": "recipe-catalog.schema.json",
    "app/collections.json": "collections.schema.json",
    "app/portal-templates.json": "portal-templates.schema.json",
    "app/decisions.json": "decisions.schema.json",
    "app/open-questions.json": "open-questions.schema.json",
    "app/action-items.json": "action-items.schema.json",
    "app/raid.json": "raid.schema.json",
    "app/roadmap.json": "roadmap.schema.json",
    "app/deliverables.json": "deliverables.schema.json",
    "app/user-stories.json": "user-stories.schema.json",
    "app/stakeholders.json": "stakeholders.schema.json",
    "app/glossary.json": "glossary.schema.json",
    "app/sessions.json": "sessions.schema.json",
    "app/assets.json": "assets.schema.json",
    "app/docs-manifest.json": "docs-manifest.schema.json",
    "app/knowledge_graph.json": "knowledge-graph.schema.json",
    "app/sources.json": "sources.schema.json",
    "app/staleness.json": "staleness.schema.json",
    "app/machine.json": "machine.schema.json",
    "analysis/artifacts/catalog.json": "artifact-catalog.schema.json",
    "client.config.json": "client.config.schema.json",
}


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def _pointer(error) -> str:
    """Human-readable JSON pointer to the offending field, e.g. items/2/type."""
    path = "/".join(str(p) for p in error.absolute_path)
    return path or "(root)"


def _validate_instance(instance, schema, validator_cls, registry):
    """Yield (pointer, message) for each schema violation, ordered."""
    validator = validator_cls(schema, registry=registry)
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        yield _pointer(err), err.message


def _iso_date_ok(value) -> bool:
    """True when value is a string holding a real YYYY-MM-DD calendar date."""
    if not isinstance(value, str) or not _DATE_RE.match(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def envelope_errors(instance):
    """Yield (pointer, message) violations of the versioned-envelope contract
    (#57 — see the module docstring for the trigger/checks rationale).

    Stdlib-only by design: the envelope is a cross-cutting convention, so it is
    enforced once here rather than duplicated (and drifting) across every
    per-artifact schema.
    """
    if not isinstance(instance, dict):
        return
    if "changelog" not in instance and not (
            "version" in instance and "updated" in instance):
        return  # envelope not adopted by this artifact
    version = instance.get("version")
    # bool is an int subclass; a `version: true` must not pass.
    if not (isinstance(version, int) and not isinstance(version, bool)
            and version >= 1):
        yield "version", "must be a positive integer (bump on every hand edit)"
    if not _iso_date_ok(instance.get("updated")):
        yield "updated", "must be a real YYYY-MM-DD date"
    changelog = instance.get("changelog")
    if not (isinstance(changelog, list) and changelog):
        yield "changelog", "must be a non-empty list of dated notes"
        return
    for i, entry in enumerate(changelog):
        if not isinstance(entry, dict):
            yield f"changelog/{i}", "must be an object with date + note"
            continue
        if not _iso_date_ok(entry.get("date")):
            yield f"changelog/{i}/date", "must be a real YYYY-MM-DD date"
        note = entry.get("note")
        if not (isinstance(note, str) and note.strip()):
            yield f"changelog/{i}/note", "must be a non-empty string"


def main() -> int:
    try:
        import jsonschema
        from jsonschema.validators import validator_for
        from referencing import Registry, Resource
    except ImportError as exc:  # pragma: no cover - environment guard
        print(f"validate-schemas: missing dependency ({exc}); "
              "install requirements.txt (jsonschema, PyYAML).", file=sys.stderr)
        return 1

    try:
        import yaml
    except ImportError:
        print("validate-schemas: missing dependency (PyYAML); "
              "install requirements.txt.", file=sys.stderr)
        return 1

    # Build a registry so $ref between schema files (knowledge-graph -> kg-node/
    # kg-edge) resolves locally without network access.
    try:
        semantic_registry = load_registry(ROOT)
    except OntologyError as exc:
        print(f"FAIL semantic registry: {exc}", file=sys.stderr)
        return 1
    resources = []
    for schema_file in SCHEMAS.glob("*.schema.json"):
        doc = json.loads(schema_file.read_text(encoding="utf-8"))
        if semantic_registry is not None:
            if schema_file.name == "brain-node.schema.json":
                doc = semantic_registry.node_schema
            elif schema_file.name == "brain-edge.schema.json":
                doc = semantic_registry.edge_schema
        resources.append((schema_file.name, Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)

    failures = 0
    checked = 0

    # 1) Whole-file JSON artifacts.
    for rel, schema_name in ARTIFACTS.items():
        target = ROOT / rel
        schema_path = SCHEMAS / schema_name
        if not schema_path.exists():
            print(f"FAIL {rel}: schema {schema_name} not found in schemas/", file=sys.stderr)
            failures += 1
            continue
        if not target.exists():
            print(f"skip {rel}: artifact not present (clean for a new engagement)")
            continue
        try:
            instance = json.loads(target.read_text(encoding="utf-8"))
        except ValueError as exc:
            print(f"FAIL {rel}: not valid JSON — {exc}", file=sys.stderr)
            failures += 1
            continue
        schema = _load_schema(schema_name)
        cls = validator_for(schema)
        errs = list(_validate_instance(instance, schema, cls, registry))
        errs += [(p, f"(versioned envelope) {m}")
                 for p, m in envelope_errors(instance)]
        checked += 1
        if errs:
            for pointer, message in errs:
                print(f"FAIL {rel} at `{pointer}`: {message}", file=sys.stderr)
            failures += 1
        else:
            print(f"ok   {rel}")

    # 2) Spec frontmatter — the leading YAML --- block of every specs/**/*.md.
    specs_schema_path = SCHEMAS / "specs-frontmatter.schema.json"
    if not specs_schema_path.exists():
        print("FAIL specs frontmatter: schema not found in schemas/", file=sys.stderr)
        failures += 1
    else:
        specs_schema = _load_schema("specs-frontmatter.schema.json")
        cls = validator_for(specs_schema)
        for md in sorted((ROOT / "specs").rglob("*.md")):
            front = _read_frontmatter(md, yaml)
            if front is None:
                continue  # no frontmatter block — not a plan node (e.g. README)
            rel = md.relative_to(ROOT)
            checked += 1
            errs = list(_validate_instance(front, specs_schema, cls, registry))
            if errs:
                for pointer, message in errs:
                    print(f"FAIL {rel} (frontmatter) at `{pointer}`: {message}", file=sys.stderr)
                failures += 1
            else:
                print(f"ok   {rel} (frontmatter)")

    # 3) Compiled brain envelope (read-only) — validated only when present, since
    # it is generated by scripts/gen-brain.py and gitignored on a fresh clone. The
    # whole {meta?, nodes, edges} document validates against brain-envelope, which
    # $refs brain-node/brain-edge per record AND contract-checks the optional
    # meta.version header (#25); meta stays optional so a header-less brain (a
    # brand-new or hand-aggregated one) still validates.
    brain = ROOT / "app" / "brain.json"
    envelope_schema_path = SCHEMAS / "brain-envelope.schema.json"
    if brain.exists() and envelope_schema_path.exists():
        envelope_schema = _load_schema("brain-envelope.schema.json")
        env_cls = validator_for(envelope_schema)
        try:
            envelope = json.loads(brain.read_text(encoding="utf-8"))
        except ValueError as exc:
            print(f"FAIL app/brain.json: not valid JSON — {exc}", file=sys.stderr)
            failures += 1
            envelope = None
        if envelope is not None:
            checked += 1
            errs = list(_validate_instance(envelope, envelope_schema, env_cls, registry))
            if not errs and semantic_registry is not None:
                try:
                    semantic_registry.validate_graph(envelope, require_binding=True)
                except OntologyError as exc:
                    errs.append(("semantic registry", str(exc)))
            if errs:
                for pointer, message in errs:
                    print(f"FAIL app/brain.json at `{pointer}`: {message}", file=sys.stderr)
                failures += 1
            else:
                print("ok   app/brain.json (brain envelope)")

    print(f"\nvalidate-schemas: {checked} artifact(s) checked, {failures} failed.")
    return 1 if failures else 0


def _read_frontmatter(path: Path, yaml) -> dict | None:
    """Return the parsed leading YAML frontmatter dict, or None if the file has
    no `---`-delimited block at the top."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return {}  # present but unparseable -> let the schema flag it as invalid
    if not isinstance(data, dict):
        return {}
    # YAML parses an unquoted `date: 2026-01-06` into a datetime.date; the schema
    # (and the downstream JSON pipeline) treats dates as ISO strings, so coerce
    # date/datetime scalars to their isoformat before validating.
    for key, val in list(data.items()):
        if isinstance(val, (datetime.date, datetime.datetime)):
            data[key] = val.isoformat()
    return data


if __name__ == "__main__":
    sys.exit(main())
