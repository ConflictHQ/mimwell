"""Composable recipe contracts and deterministic, use-case-specific collection coverage.

The planner checks declarations and local component presence. It neither executes
discovered code nor claims that a deployment, policy or source assertion is verified.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

from jsonschema import Draft202012Validator
from ontology import Registry, _acyclic

ROOT = Path(__file__).resolve().parents[1]
ARRAYS = ("consumers", "ontologyLayers", "collectionProfiles", "components", "requirements", "practices", "stores", "surfaces")
SINGLES = ("purpose", "subject", "scope", "runtime", "federation")


class RecipeError(ValueError):
    pass


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def binding(value):
    return {"id": value["id"], "version": value["version"], "sha256": fingerprint(value)}


def timestamp(value):
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError("timezone required")
        return result.astimezone(dt.timezone.utc)
    except (TypeError, ValueError) as exc:
        raise RecipeError(f"invalid timezone-aware timestamp: {value!r}") from exc


def _validate(value, schema):
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
    if errors:
        raise RecipeError("\n".join(f"/{'/'.join(map(str, e.path))}: {e.message}" for e in errors))


def _unique(items, label, key=lambda x: x["id"]):
    result = {}
    for item in items:
        identity = key(item)
        if identity in result:
            raise RecipeError(f"{label}: duplicate {identity!r}")
        result[identity] = item
    return result


def duplicate_identities(documents):
    """(section, id, version) for every entry in recipes, components or
    collectionProfiles that repeats an exact (id, version) pair already seen in
    the given raw catalog documents. Reads the documents directly and reports
    every section's duplicates, independent of and before any Catalog is built."""
    duplicates = []
    for section in ("recipes", "components", "collectionProfiles"):
        seen = set()
        for doc in documents:
            for item in doc.get(section, []):
                pair = (item["id"], item["version"])
                if pair in seen:
                    duplicates.append((section, *pair))
                else:
                    seen.add(pair)
    return duplicates


def _safe_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or any(
            (root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise RecipeError(f"component file must be local and cannot follow symlinks: {relative}")
    return (root / path).is_file()


class Catalog:
    def __init__(self, documents, engine_root=ROOT):
        self.root = Path(engine_root)
        self.schema = json.loads((ROOT / "schemas/recipe-catalog.schema.json").read_text())
        merged = {key: [] for key in ("recipes", "components", "collectionProfiles")}
        for doc in documents:
            _validate(doc, self.schema)
            for key in merged:
                merged[key].extend(doc[key])
        self.index = {key: _unique(items, key, lambda x: (x["id"], x["version"])) for key, items in merged.items()}

    def get(self, section, reference):
        key = (reference["id"], reference["version"])
        try:
            return self.index[section][key]
        except KeyError as exc:
            raise RecipeError(f"{section}: unavailable declaration {key[0]}@{key[1]}") from exc

    def resolve(self, reference):
        ordered, visiting, seen = [], set(), {}

        def walk(ref):
            item = self.get("recipes", ref)
            key = (item["id"], item["version"])
            if key in visiting:
                raise RecipeError(f"recipe inheritance cycle at {key}")
            if item["id"] in seen:
                if seen[item["id"]] != item["version"]:
                    raise RecipeError(f"recipe dependency version collision: {item['id']}")
                return
            visiting.add(key)
            for parent in item["extends"]:
                walk(parent)
            visiting.remove(key)
            seen[item["id"]] = item["version"]
            ordered.append(item)

        walk(reference)
        final = ordered[-1]
        if final["type"] != "recipe":
            raise RecipeError("a fragment cannot be executed as a complete recipe")
        output = {key: deepcopy(final[key]) for key in ("id", "version", "type", "extends")}
        arrays = {key: {} for key in ARRAYS}
        for layer in ordered:
            for key in SINGLES:
                if key not in layer:
                    continue
                if key in output and output[key] != layer[key]:
                    raise RecipeError(f"recipe {layer['id']}: conflicting {key}; no implicit override")
                output[key] = deepcopy(layer[key])
            for key in ARRAYS:
                for value in layer.get(key, []):
                    identity = value["id"]
                    if identity in arrays[key] and arrays[key][identity] != value:
                        raise RecipeError(f"recipe {layer['id']}: {key} collision for {identity}")
                    arrays[key][identity] = deepcopy(value)
        output.update({key: list(values.values()) for key, values in arrays.items()})
        _validate(output, {"$ref": "#/$defs/resolved", "$defs": self.schema["$defs"]})
        return output, [binding(layer) for layer in ordered]

    def ontology(self, recipe):
        layers = recipe["ontologyLayers"]
        bases = [x for x in layers if x["role"] == "base"]
        if len(bases) != 1:
            raise RecipeError("recipe requires exactly one ontology base")
        for layer in layers:
            if not _safe_file(self.root, "profiles/" + layer["id"] + ".json"):
                raise RecipeError(f"ontology profile is not installed: {layer['id']}")
        spec = importlib.util.spec_from_file_location("recipe_composer", ROOT / "scripts/compose-schema.py")
        composer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(composer)
        composer.PROFILES = str(self.root / "profiles")
        try:
            declaration = composer.compose(bases[0]["id"], [x["id"] for x in layers if x["role"] == "overlay"])
        except SystemExit as exc:
            raise RecipeError(str(exc)) from exc
        if "registry" not in declaration:
            raise RecipeError("selected ontology requires semantic registry support")
        for layer in layers:
            if declaration["registry"]["layers"].get(layer["id"]) != layer["version"]:
                raise RecipeError(f"ontology layer version mismatch: {layer['id']}@{layer['version']}")
        return Registry(declaration)

    def questions(self, recipe, ontology):
        questions, profiles = {}, []
        use_cases = {case for consumer in recipe["consumers"] for case in consumer["useCases"]}
        for ref in recipe["collectionProfiles"]:
            profile = self.get("collectionProfiles", ref)
            profiles.append(binding(profile))
            for question in profile["questions"]:
                if question["id"] in questions:
                    raise RecipeError(f"duplicate collection question: {question['id']}")
                term = ontology.terms.get(question["category"])
                if term is None or term["scheme"] != "collection":
                    raise RecipeError(f"question {question['id']}: unknown collection category")
                if question["useCase"] not in use_cases:
                    raise RecipeError(f"question {question['id']}: no consumer for use case {question['useCase']}")
                questions[question["id"]] = {**question, "profile": binding(profile)}
        if not questions:
            raise RecipeError("a recipe must declare at least one collection question")
        return questions, profiles

    def components(self, recipe):
        selected, walking = {}, set()

        def visit(ref):
            component = self.get("components", ref)
            identity = component["id"]
            if identity in walking:
                raise RecipeError(f"component dependency cycle: {identity}")
            if identity in selected:
                if selected[identity]["version"] != ref["version"]:
                    raise RecipeError(f"component version collision: {identity}")
                return
            walking.add(identity)
            for dep in component["dependencies"]:
                visit(dep)
            walking.remove(identity)
            selected[identity] = component

        for ref in recipe["components"]:
            visit(ref)
        providers = {}
        for identity, component in selected.items():
            for capability in component["provides"]:
                if capability["id"] in providers:
                    raise RecipeError(f"ambiguous capability providers: {capability['id']}")
                providers[capability["id"]] = {**capability, "component": identity}
        graph, observations = {}, {}
        for identity, component in selected.items():
            implementation = component["implementation"]
            files = _unique(implementation["files"], f"component {identity} files", lambda f: f["path"])
            missing_files, changed_files = [], []
            for path, descriptor in files.items():
                if not _safe_file(self.root, path):
                    missing_files.append(path)
                elif hashlib.sha256((self.root / path).read_bytes()).hexdigest() != descriptor["sha256"]:
                    changed_files.append(path)
            missing_runtimes = [name for name in implementation["runtimes"] if shutil.which(name) is None]
            reasons = []
            if implementation["mode"] != "local":
                reasons.append("external implementation is not observed by this local planner")
            elif not implementation["files"]:
                raise RecipeError(f"local component {identity} requires implementation files")
            if missing_files:
                reasons.append("missing files: " + ", ".join(missing_files))
            if changed_files:
                reasons.append("file revision mismatch: " + ", ".join(changed_files))
            if missing_runtimes:
                reasons.append("missing runtimes: " + ", ".join(missing_runtimes))
            graph[identity] = [dep["id"] for dep in component["dependencies"]]
            for need in component["requires"]:
                provider = providers.get(need["id"])
                if provider is None or provider["version"] != need["version"]:
                    reasons.append(f"missing producer/version for {need['id']}@{need['version']}")
                else:
                    graph[identity].append(provider["component"])
            observations[identity] = {"binding": binding(component), "localReasons": reasons,
                                      "verification": "pinned-file-fingerprints-and-executable-presence", "runtimeVerified": False}
        _acyclic(graph, "component requirements")
        available = {key for key, value in observations.items() if not value["localReasons"]}
        while True:
            reduced = {key for key in available if all(dep in available for dep in graph[key])}
            if reduced == available:
                break
            available = reduced
        for identity, observation in observations.items():
            observation["available"] = identity in available
            observation["unavailableDependencies"] = sorted(set(graph[identity]) - available)
        return providers, observations

    def runtime_verified(self, recipe):
        """Whether every store the recipe declares as an authority (#200, replacing
        the always-False top-level `runtimeVerified`) has a green cell-conformance
        receipt for its driver, under this engine root's
        proofs/*/*cell-conformance.json: `knowledge-store.py conformance` (#224) for
        the driver-backed cells (sqlite, postgres, mysql), or, for `files` — a
        read-only reference with no server and so no conformance cell of its own —
        the fixed set of authority contract tests that build or target it directly
        (`proofs/ks7/files_cell_conformance.py`, #325). Every shipped example scaffolds
        `files` by default (the files-by-default ADR,
        docs/design/adr-authority-per-brain-kind.md), so this is the receipt that makes
        a shipped recipe reachable, not a recipe with literally no authority store
        (which has nothing a conformance suite verifies and reports verified). This is
        still a local, static check: it trusts the receipt's own claim rather than
        re-running the suite (component-level `runtimeVerified` above stays False for
        the same reason this module's docstring gives — it does not execute discovered
        code)."""
        needed = sorted({store["driver"] for store in recipe["stores"] if store["authorities"]})
        if not needed:
            return True
        verified_drivers = set()
        for path in sorted(self.root.glob("proofs/*/*cell-conformance.json")):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for cell in (doc.get("cells") or {}).values():
                receipt = cell.get("receipt") or {}
                if receipt.get("format") != "cell-conformance/v1" or receipt.get("result") != "green":
                    continue
                driver = (receipt.get("cell") or "").partition("authority=")[2].split(",")[0].strip()
                if driver:
                    verified_drivers.add(driver)
        return all(driver in verified_drivers for driver in needed)

    def plan(self, reference, *, as_of, assessment=None):
        at = timestamp(as_of)
        recipe, lineage = self.resolve(reference)
        ontology = self.ontology(recipe)
        questions, profiles = self.questions(recipe, ontology)
        providers, components = self.components(recipe)
        practices = {p["id"]: p for p in recipe["practices"]}
        authorities = []
        requirements = list(recipe["requirements"])
        for store in recipe["stores"]:
            if store["authorities"] and not set(store["roles"]).intersection({"records", "evidence", "journal", "external-authority"}):
                raise RecipeError(f"projection/backup {store['id']} cannot claim source authority")
            if store["authorities"] and store.get("writerPractice") not in practices:
                raise RecipeError(f"store {store['id']}: authority needs a declared writer practice")
            for authority in store["authorities"]:
                for previous in authorities:
                    same_collection = authority["collection"] == previous["collection"] or "*" in (authority["collection"], previous["collection"])
                    overlapping = bool(set(authority["fields"]) & set(previous["fields"])) or "*" in authority["fields"] or "*" in previous["fields"]
                    if same_collection and overlapping:
                        raise RecipeError(f"authority collision: {store['id']} and {previous['store']}")
                authorities.append({**authority, "store": store["id"]})
            requirements.extend({**need, "required": store["required"]} for need in store["requires"])
        for surface in recipe["surfaces"]:
            requirements.extend({**need, "required": True} for need in surface["requires"])
        needs = {}
        for need in requirements:
            old = needs.get(need["id"])
            if old and old["version"] != need["version"]:
                raise RecipeError(f"capability requirement version collision: {need['id']}")
            needs[need["id"]] = {**need, "required": need.get("required", True) or bool(old and old["required"])}
        required_gaps, optional_gaps = [], []
        for identity, need in sorted(needs.items()):
            provider = providers.get(identity)
            reason = "missing-producer" if provider is None else "version-mismatch" if provider["version"] != need["version"] else (
                "unavailable-component" if not components[provider["component"]]["available"] else None)
            if reason:
                (required_gaps if need["required"] else optional_gaps).append({"capability": identity, "version": need["version"], "reason": reason})
        for runtime in recipe["runtime"]["requires"]:
            if shutil.which(runtime) is None:
                required_gaps.append({"runtime": runtime, "reason": "missing-runtime"})
        if recipe["runtime"]["mode"] == "hosted":
            required_gaps.append({"runtime": "hosted", "reason": "deployment-not-verified-by-local-planner"})
        coverage = assess(questions, assessment, at)
        return {"protocolVersion": "1.0", "asOf": at.isoformat(), "recipe": recipe, "binding": binding(recipe),
                "lineage": lineage, "ontology": ontology.binding(), "collectionProfiles": profiles,
                "components": components, "requiredGaps": required_gaps, "optionalGaps": optional_gaps,
                "requirementsSatisfied": not required_gaps, "runtimeVerified": self.runtime_verified(recipe),
                "evidenceInventory": deepcopy(assessment["evidence"]) if assessment else [],
                "coverage": coverage, "coverageSatisfied": all(c["state"] in ("sufficient", "not-applicable") for c in coverage)}


def assess(questions, document, at):
    if document is None:
        document = {"protocolVersion": "1.0", "evidence": [], "assessments": []}
    schema = json.loads((ROOT / "schemas/collection-assessment.schema.json").read_text())
    _validate(document, schema)
    evidence = _unique(document["evidence"], "evidence")
    assessments = _unique(document["assessments"], "assessments", lambda x: x["question"])
    if set(assessments) - questions.keys():
        raise RecipeError("assessment names an unknown collection question")
    for source in evidence.values():
        if timestamp(source["observedAt"]) > at:
            raise RecipeError(f"evidence {source['id']}: observation is after as-of")
    output = []
    for identity, question in sorted(questions.items()):
        assessment = assessments.get(identity)
        entry = {"question": identity, "useCase": question["useCase"], "category": question["category"],
                 "text": question["text"], "cadence": deepcopy(question["cadence"]),
                 "evidenceRequirements": deepcopy(question["evidence"]),
                 "profile": question["profile"], "criterion": question["criterion"], "ownerRole": question["ownerRole"],
                 "state": "missing", "reasons": ["no assessment"], "evidence": []}
        if assessment:
            if assessment["useCase"] != question["useCase"]:
                raise RecipeError(f"question {identity}: assessment belongs to another use case")
            reviewed = timestamp(assessment["reviewedAt"])
            if reviewed > at:
                raise RecipeError(f"question {identity}: review is after as-of")
            if set(assessment["evidence"]) - evidence.keys():
                raise RecipeError(f"question {identity}: unknown evidence reference")
            sources = [evidence[key] for key in sorted(set(assessment["evidence"]))]
            reasons = []
            stale = assessment["profile"] != question["profile"] or assessment["criterion"] != question["criterion"]
            if stale:
                reasons.append("collection profile or criterion changed")
            age = dt.timedelta(days=question["cadence"]["maxAgeDays"])
            if at - reviewed > age or any(at - timestamp(s["observedAt"]) > age for s in sources):
                stale = True
                reasons.append("review or evidence exceeds collection cadence")
            if any(s["revision"] != s["currentRevision"] for s in sources):
                stale = True
                reasons.append("evidence revision changed")
            if any(timestamp(s["observedAt"]) > reviewed for s in sources):
                stale = True
                reasons.append("evidence observation is newer than review")
            if assessment["decision"] == "not-applicable":
                if not question["allowNotApplicable"] or sources:
                    raise RecipeError(f"question {identity}: not-applicable is disallowed or carries evidence")
                state = "not-applicable"
            else:
                if len({s["lineage"] for s in sources}) < question["evidence"]["minSources"]:
                    reasons.append("insufficient independent source lineages")
                if set(question["evidence"]["modalities"]) - {s["modality"] for s in sources}:
                    reasons.append("required evidence modalities missing")
                if assessment["decision"] != "sufficient":
                    reasons.append("review has not established sufficiency")
                state = "missing" if not sources else "partial" if reasons else "sufficient"
            if stale:
                state = "stale"
            entry.update({"state": state, "reasons": reasons, "evidence": [s["id"] for s in sources],
                          "reviewedAt": assessment["reviewedAt"],
                          "reviewedBy": assessment["reviewedBy"], "reason": assessment["reason"]})
        output.append(entry)
    return output
