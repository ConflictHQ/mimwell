"""Version-bound component discovery using the existing recipe resolver.

Discovery is a local operator inspection. It never executes catalog commands,
activates a module, changes knowledge, or grants access to a participant.
"""

from collections import OrderedDict
from copy import copy, deepcopy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing.exceptions import Unresolvable

from brain_recipes import RecipeError, ROOT, _safe_file, binding, fingerprint, timestamp
from ontology import Registry

MAX_FILE_BYTES = 16 * 1024 * 1024
SCHEMA_MEMO_ENTRIES = 64
SCHEMA_MEMO_BYTES = 2 * 1024 * 1024
SCHEMA_MEMO_KEY_BYTES = 256 * 1024


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise RecipeError("Discovery input exceeds the file limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RecipeError("Duplicate JSON member")
            result[key] = value
        return result

    def invalid(value):
        raise RecipeError("Non-finite JSON number")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            invalid(value)
        return number

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)


def local_json(root, relative):
    root = Path(root)
    if root.is_symlink() or not _safe_file(root, relative):
        raise RecipeError("Selected local input is unavailable")
    return read_json(root / relative)


def _schema_memo_key(schema):
    # Only exact JSON content participates. Other Python objects keep the old
    # uncached validator behavior instead of sharing a potentially lossy key.
    pending, seen, work = [schema], set(), 0
    try:
        while pending:
            item = pending.pop()
            work += 1
            if work > SCHEMA_MEMO_KEY_BYTES:
                return None
            if type(item) in (dict, list):
                if id(item) in seen:
                    return None
                seen.add(id(item))
            if type(item) is dict:
                if work + len(item) > SCHEMA_MEMO_KEY_BYTES:
                    return None
                if any(type(key) is not str for key in item):
                    return None
                work += sum(map(len, item))
                if work + len(item) > SCHEMA_MEMO_KEY_BYTES:
                    return None
                pending.extend(item.values())
            elif type(item) is list:
                if work + len(item) > SCHEMA_MEMO_KEY_BYTES:
                    return None
                pending.extend(item)
            elif type(item) is str:
                work += len(item)
            elif type(item) not in (int, float, bool, type(None)):
                return None
        if work > SCHEMA_MEMO_KEY_BYTES:
            return None
        raw = bytearray()
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False)
        for part in encoder.iterencode(schema):
            part = part.encode("utf-8")
            if len(raw) + len(part) > SCHEMA_MEMO_KEY_BYTES:
                return None
            raw.extend(part)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None
    return bytes(raw)


def validate_schema(schema, *, _memo=None):
    key = _schema_memo_key(schema) if _memo is not None else None
    if key is not None and key in _memo:
        _memo.move_to_end(key)
        return
    try:
        Draft202012Validator.check_schema(schema)
    except (SchemaError, RecursionError) as exc:
        raise RecipeError("Invalid discovery validation schema") from exc

    def walk(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key in ("$ref", "$dynamicRef") and not value.startswith("#"):
                    raise RecipeError("Discovery schemas cannot retrieve external references")
                walk(value)
        elif isinstance(item, list):
            for value in item:
                walk(value)

    walk(schema)
    # Positive schema checks only: no validator, input data, file freshness,
    # access decision or schema object is retained. Recompute content each call.
    if key is not None:
        _memo[key] = None
        while len(_memo) > SCHEMA_MEMO_ENTRIES or sum(map(len, _memo)) > SCHEMA_MEMO_BYTES:
            _memo.popitem(last=False)


def validate_json(value, schema, *, _memo=None):
    validate_schema(schema, _memo=_memo)
    try:
        if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(value):
            raise RecipeError("Input does not satisfy its declared schema")
    except (Unresolvable, RecursionError) as exc:
        raise RecipeError("Unresolvable discovery validation schema") from exc


def load_script(name):
    # Only this engine's fixed, reviewed validators are loadable. A catalog
    # cannot supply executable code or replace these paths through --root.
    spec = importlib.util.spec_from_file_location("discovery_" + name, ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded_kind_reference(schema, node):
    seen = set()
    for _ in range(64):
        if not isinstance(node, dict) or "$ref" not in node:
            return node
        reference = node["$ref"]
        if reference in seen or not reference.startswith("#/"):
            raise RecipeError("Cyclic or unsupported kind descriptor schema reference")
        seen.add(reference)
        node = schema
        for part in reference.split("/")[1:]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
    raise RecipeError("Kind descriptor schema reference limit exceeded")


class Discovery:
    def __init__(self, catalog, document):
        self.catalog = catalog
        self._schema_memo = OrderedDict()
        self.document = deepcopy(document)
        schema = read_json(ROOT / "schemas/component-discovery.schema.json")
        validate_json(document, schema, _memo=self._schema_memo)
        self.entries = {}
        for item in document["entries"]:
            key = (item["id"], item["version"])
            if key in self.entries:
                raise RecipeError("Duplicate component discovery identity")
            self.entries[key] = item
            validate_schema(item["settingsSchema"], _memo=self._schema_memo)
            if item["component"]:
                declared = catalog.get("components", item["component"])
                if binding(declared) != item["component"]:
                    raise RecipeError("Component discovery binding disagrees with recipe registry")
            elif not item["gapIssues"]:
                raise RecipeError("Unpackaged entries must name a gap issue")
            for contract in item["inputs"]:
                if contract["schema"]:
                    descriptor = contract["schema"]
                    if not _safe_file(catalog.root, descriptor["path"]):
                        continue  # Missing installation is an observation, not a false readiness claim.
                    if (
                        hashlib.sha256((catalog.root / descriptor["path"]).read_bytes()).hexdigest()
                        != descriptor["sha256"]
                    ):
                        continue
                    validate_schema(local_json(catalog.root, descriptor["path"]), _memo=self._schema_memo)

    def candidates(
        self, *, identity=None, version=None, need=None, family=None, use_case=None, capability=None, input_id=None
    ):
        output = []
        for item in sorted(self.entries.values(), key=lambda entry: (entry["id"], entry["version"])):
            if identity and identity != item["id"]:
                continue
            if version and version != item["version"]:
                continue
            words = " ".join([item["id"], item["title"], item["description"], *item["informationNeeds"]]).casefold()
            if need and not all(word in words for word in need.casefold().split()):
                continue
            if family and family not in item["labels"]["families"]:
                continue
            if use_case and use_case not in item["useCases"]:
                continue
            if input_id and input_id not in {x["id"] for x in item["inputs"]}:
                continue
            if capability:
                if not item["component"]:
                    continue
                component = self.catalog.get("components", item["component"])
                if capability not in component["provides"]:
                    continue
            output.append(item)
        return output

    def input_report(self, contract, root, *, as_of):
        result = {
            "id": contract["id"],
            "path": contract["path"],
            "required": contract["required"],
            "state": "not-inspected",
            "sha256": None,
            "validator": contract["validator"],
        }
        if root is None:
            return result
        try:
            value = local_json(root, contract["path"])
            # This canonical digest binds the exact parsed value inspected, including semantic checks.
            result["sha256"] = fingerprint(value)
            descriptor = contract["schema"]
            if descriptor:
                path = self.catalog.root / descriptor["path"]
                if (
                    not _safe_file(self.catalog.root, descriptor["path"])
                    or hashlib.sha256(path.read_bytes()).hexdigest() != descriptor["sha256"]
                ):
                    raise RecipeError("Contract schema is missing or changed")
                validate_json(value, local_json(self.catalog.root, descriptor["path"]), _memo=self._schema_memo)
            validator = contract["validator"]
            if validator == "brain-graph":
                ontology = local_json(root, "brain-schema.json")
                Registry(ontology).validate_graph(value, require_binding=True)
                result["ontologySha256"] = fingerprint(ontology)
            elif validator == "kind-descriptors":
                composer = load_script("gen-kinds.py")
                composer._resolve = bounded_kind_reference
                ontology = local_json(root, "brain-schema.json")

                def artifact_schema(artifact):
                    name = composer.SCHEMA_FOR.get(artifact) or Path(artifact).name.replace(".json", ".schema.json")
                    path = "schemas/" + name
                    if not _safe_file(Path(root), path):
                        return None
                    schema = local_json(root, path)
                    validate_schema(schema, _memo=self._schema_memo)
                    return schema

                composer._artifact_schema = artifact_schema
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "brain-schema.json"
                    path.write_text(json.dumps(ontology))
                    expected = composer.build(str(path))
                if value != expected:
                    raise RecipeError("Kind descriptors disagree with their source declarations")
                result["ontologySha256"] = fingerprint(ontology)
            elif validator == "blueprint":
                checker = load_script("check-machine.py")
                decisions = local_json(root, "app/decisions.json")
                ids = {row["id"] for row in decisions.get("decisions", []) if row.get("id")}
                errors, notes = checker.check(value, decisions_ids=ids or None, today=timestamp(as_of).date())
                if errors:
                    raise RecipeError("Blueprint evidence or reference gate failed")
                result["evidenceCheck"] = "declared-references-only"
                result["decisionBasis"] = fingerprint(decisions)
                result["notesCount"] = len(notes)
            elif validator == "simulator":
                # Fixed validator checks a disposable copy. No input-derived code runs.
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "machine.json"
                    path.write_text(json.dumps(value, allow_nan=False))
                    process = subprocess.run(
                        [sys.executable, str(ROOT / "simulator/data/check-machine.py"), str(path)],
                        capture_output=True,
                        timeout=20,
                    )
                    if process.returncode:
                        raise RecipeError("Simulator evidence or geometry gate failed")
                result["evidenceCheck"] = "declared-references-only"
            result["state"] = "valid"
        except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
            # Do not print private records or distinguish denied from missing sources.
            result["state"] = "unavailable-or-invalid"
        return result

    def inspect(self, item, *, as_of, recipe=None, data_root=None, settings=None):
        timestamp(as_of)
        selected = deepcopy(item)
        selected.update(
            {
                "observationAt": as_of,
                "implementationAvailable": False,
                "recipeCompatible": None,
                "runtimeVerified": False,
                "activated": False,
                "authorizationVerified": False,
                "gaps": [],
                "componentObservations": {},
                "launch": [],
            }
        )
        if timestamp(item["observedAt"]) > timestamp(as_of):
            raise RecipeError("Discovery observation is after the requested time")
        settings = settings if settings is not None else {}
        validate_json(settings, item["settingsSchema"], _memo=self._schema_memo)
        selected["settings"] = deepcopy(settings)
        reference = item["component"]
        if reference is None:
            selected["gaps"].append("No registered executable component; inspect the linked gap issues")
        else:
            try:
                if recipe:
                    # Preview through Catalog.plan, using an isolated in-memory recipe
                    # extension. No second dependency/capability resolver is introduced.
                    preview = copy(self.catalog)
                    identity = "discovery.preview." + item["id"]
                    declaration = {
                        "id": identity,
                        "version": item["version"],
                        "type": "recipe",
                        "extends": [recipe],
                        "components": [{"id": reference["id"], "version": reference["version"]}],
                    }
                    preview.index = {
                        **self.catalog.index,
                        "recipes": {**self.catalog.index["recipes"], (identity, item["version"]): declaration},
                    }
                    plan = preview.plan({"id": identity, "version": item["version"]}, as_of=as_of)
                    observations = plan["components"]
                    selected["recipeCompatible"] = plan["requirementsSatisfied"]
                    selected["recipeGaps"] = plan["requiredGaps"]
                    selected["recipeBinding"] = plan["lineage"]
                    selected["recipeOntology"] = plan["ontology"]
                else:
                    _, observations = self.catalog.components({"components": [reference]})
                selected["componentObservations"] = observations
                selected["implementationAvailable"] = observations[reference["id"]]["available"]
                if not selected["implementationAvailable"]:
                    selected["gaps"].append("Pinned implementation or dependency is unavailable")
            except RecipeError as exc:
                selected["recipeCompatible"] = False if recipe else None
                selected["gaps"].append(str(exc))
        selected["inputObservations"] = [
            self.input_report(contract, data_root, as_of=as_of) for contract in item["inputs"]
        ]
        if (
            recipe
            and data_root is not None
            and any(c["validator"] in ("brain-graph", "kind-descriptors") for c in item["inputs"])
        ):
            try:
                actual = Registry(local_json(data_root, "brain-schema.json")).binding()
                if actual != selected.get("recipeOntology"):
                    raise RecipeError("Input ontology differs from the selected recipe")
            except (ValueError, OSError, KeyError, TypeError):
                selected["recipeCompatible"] = False
                selected["gaps"].append("Selected input ontology is unavailable or differs from the recipe")
        if item["id"] == "kind-views":
            selected["embedding"] = {
                "tag": "main",
                "class": "kind-page",
                "data-kb-kinds": ",".join(settings.get("kinds", [])),
                "script": "/app/kind-page.js",
                "stylesheet": "/app/kind-page.css",
            }
            selected["inputObservations"].extend(self.kind_inputs(settings.get("kinds", []), data_root))
        elif item["id"] == "glossary":
            selected["inputObservations"].extend(
                self.kind_inputs(
                    ["glossary-term"], data_root, expected={"glossary-term": ("app/glossary.json", "terms")}
                )
            )
        required = [r for r in selected["inputObservations"] if r["required"]]
        selected["inputsValid"] = bool(item["contractsVerified"]) and all(r["state"] == "valid" for r in required)
        if not selected["inputsValid"]:
            selected["gaps"].append("Required input contracts are unverified, uninspected or unsatisfied")
        for output in item["outputs"]:
            if output["href"]:
                query = {key: settings[key] for key in output["querySettings"] if key in settings}
                selected["launch"].append(
                    {"id": output["id"], "href": output["href"] + ("?" + urlencode(query) if query else "")}
                )
        selected["usableWithInspectedInputs"] = (
            selected["implementationAvailable"]
            and selected["inputsValid"]
            and selected["recipeCompatible"] is not False
        )
        return selected

    def kind_inputs(self, kinds, root, expected=None):
        if not kinds or root is None:
            return [{"id": "records.selected-kinds", "required": True, "state": "not-inspected"}]
        output = []
        try:
            descriptors = local_json(root, "app/kinds.json")
            by_id = {item["id"]: item for item in descriptors["kinds"]}
            composer = load_script("gen-kinds.py")
            for identity in kinds:
                entry = by_id.get(identity)
                if not entry or not entry.get("renderable"):
                    raise RecipeError("Selected kind is unavailable or not a flat renderable kind")
                if expected and (entry.get("artifact"), entry.get("records")) != expected.get(identity):
                    raise RecipeError("Selected kind does not satisfy the fixed page contract")
                path = entry["artifact"]
                data = local_json(root, path)
                name = composer.SCHEMA_FOR.get(path) or Path(path).name.replace(".json", ".schema.json")
                schema = local_json(root, "schemas/" + name)
                validate_json(data, schema, _memo=self._schema_memo)
                if not isinstance(data.get(entry["records"]), list):
                    raise RecipeError("Record collection must be a list")
                output.append(
                    {
                        "id": identity,
                        "path": path,
                        "required": True,
                        "state": "valid",
                        "sha256": fingerprint(data),
                        "schemaSha256": fingerprint(schema),
                    }
                )
        except (ValueError, OSError, KeyError, TypeError):
            return [{"id": "records.selected-kinds", "required": True, "state": "unavailable-or-invalid"}]
        return output

    def discover(self, *, as_of, recipe=None, data_root=None, settings=None, limit=50, **filters):
        if not 1 <= limit <= 200:
            raise RecipeError("Discovery limit must be between 1 and 200")
        entries = self.candidates(**filters)
        results = [
            self.inspect(entry, as_of=as_of, recipe=recipe, data_root=data_root, settings=settings)
            for entry in entries[:limit]
        ]
        return {
            "protocolVersion": "1.0",
            "asOf": as_of,
            "catalogBasis": fingerprint(self.document),
            "matched": len(entries),
            "truncated": len(entries) > limit,
            "results": results,
            "activated": False,
            "authorizationVerified": False,
            "runtimeVerified": False,
        }
