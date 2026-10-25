"""Read-only semantic authoring context from selected, versioned declarations.

This is an operator-side metadata reader, not an authenticated record service or
writer. It does not read source records, crawl participants or execute tools.
"""

from copy import deepcopy
import hashlib
import json

from brain_recipes import ROOT, RecipeError, _safe_file, binding, fingerprint
from component_discovery import local_json, validate_json
from component_interfaces import MAX_BYTES, MAX_SCHEMAS, contract_schema, parse_json
from evidence import MISSING, _pointer


CHANGE_ROUTES = {
    "taxonomy": "Extend controlled terms/aliases/broader links in a versioned ontology overlay; retain record IDs and local labels.",
    "ontology": "Propose a versioned kind/relation/payload contract change; validate producer and consumer compatibility before adoption.",
    "view": "Select declarative experience/layout/navigation settings through the reviewed experience workflow; knowledge identity does not change.",
    "source": "Use the owning participant's declared writer and source adapter; moving a source requires identity/provenance preservation.",
    "storage": "Use the explicit authority migration and backup/recovery workflow; a graph encoding switch does not migrate record ownership.",
}


def schema_fields(schema):
    """Expose field constraints without inventing meaning or resolving remote refs.

    Branches and refs retain their schema coordinates. `requiredHere` only applies
    within that schema object, not unconditionally to every record instance.
    """
    result = []

    def walk(value, pointer, depth=0):
        if depth > 64:
            raise RecipeError("Authoring schema nesting exceeds 64 levels")
        if isinstance(value, dict):
            props = value.get("properties", {})
            if isinstance(props, dict):
                for name, constraint in props.items():
                    escaped = name.replace("~", "~0").replace("/", "~1")
                    if not isinstance(constraint, (dict, bool)):
                        raise RecipeError("Invalid property schema")
                    details = constraint if isinstance(constraint, dict) else {}
                    result.append({
                        "name": name,
                        "schemaPointer": pointer + "/properties/" + escaped,
                        "purpose": details.get("description", details.get("title")),
                        "purposeState": "declared" if details.get("description", details.get("title")) else "unspecified",
                        "requiredHere": name in value.get("required", []),
                        "constraint": deepcopy(constraint),
                        "examples": deepcopy(details.get("examples", [])),
                        "unknownRule": "Missing meaning or examples are gaps; do not invent values to satisfy a required field.",
                    })
            for key in ("$defs", "definitions", "properties", "patternProperties", "dependentSchemas"):
                for name, child in value.get(key, {}).items():
                    walk(child, pointer + "/" + key + "/" + name.replace("~", "~0").replace("/", "~1"), depth + 1)
            for key in ("items", "additionalProperties", "unevaluatedProperties", "contains",
                        "propertyNames", "if", "then", "else", "not", "additionalItems",
                        "unevaluatedItems", "allOf", "anyOf", "oneOf", "prefixItems"):
                if key in value:
                    walk(value[key], pointer + "/" + key, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, pointer + "/" + str(index), depth + 1)

    walk(schema, "")
    return result


def task_catalog(root=ROOT):
    document = local_json(root, "practices/semantic-authoring.json")
    validate_json(document, local_json(ROOT, "schemas/semantic-authoring.schema.json"))
    identities = [task["id"] for task in document["tasks"]]
    if len(identities) != len(set(identities)):
        raise RecipeError("Duplicate authoring task identity")
    for task in document["tasks"]:
        for path in task["references"]:
            if not _safe_file(root, path):
                raise RecipeError("Authoring task reference is not installed: " + path)
    return document


def field_hints(document, path, schema):
    hints = {}
    for item in document["fieldHints"]:
        if item["schema"] != path:
            continue
        pointer = item["pointer"]
        if pointer in hints:
            raise RecipeError("Duplicate authoring field hint")
        if item["schemaSha256"] != fingerprint(schema):
            raise RecipeError("Field hints are stale for selected schema: " + path)
        value = _pointer(schema, pointer)
        if value is MISSING:
            raise RecipeError("Field hint does not address the selected schema")
        if not isinstance(value, (dict, bool)):
            raise RecipeError("Field hint must describe a schema")
        hints[pointer] = deepcopy(item)
    return hints


def schema_inputs(root, paths):
    """Use the interface resolver for an explicitly selected local closure."""
    paths = sorted(set(paths))
    if len(paths) > MAX_SCHEMAS:
        raise RecipeError("Authoring schema selection exceeds 32 files")
    documents, pins, total = {}, [], 0
    for path in paths:
        if root.is_symlink() or not _safe_file(root, path):
            raise RecipeError("Authoring schema must be an installed local nonsymlinked file")
        with (root / path).open("rb") as stream:
            raw = stream.read(MAX_BYTES - total + 1)
        total += len(raw)
        if total > MAX_BYTES:
            raise RecipeError("Authoring schema selection exceeds 4 MiB")
        documents[path] = parse_json(raw)
        pins.append({"path": path, "sha256": hashlib.sha256(raw).hexdigest()})
    for pin in pins:
        contract_schema(root, {"schema": None, "pointer": "", "schemaFiles": [
            pin, *[other for other in pins if other is not pin]
        ]})
    return documents, pins


def describe(catalog, reference, *, as_of, task=None, schemas=(), assessment=None,
             expected_basis=None, max_bytes=2 * 1024 * 1024):
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 16 * 1024 * 1024:
        raise RecipeError("Authoring output budget must be 1 KiB to 16 MiB")
    plan = catalog.plan(reference, as_of=as_of, assessment=assessment)
    recipe = plan["recipe"]
    registry = catalog.ontology(recipe)
    document = task_catalog(catalog.root)
    tasks = [row for row in document["tasks"] if task is None or row["id"] == task]
    if not tasks:
        raise RecipeError("Unknown authoring task")
    providers, observations = catalog.components(recipe)
    selected_tasks = []
    for row in tasks:
        item = deepcopy(row)
        item["referenceBindings"] = [
            {"path": path, "sha256": hashlib.sha256((catalog.root / path).read_bytes()).hexdigest()}
            for path in row["references"]
        ]
        item["tools"] = []
        for need in row["capabilities"]:
            provider = providers.get(need["id"])
            compatible = provider is not None and provider["version"] == need["version"]
            component = catalog.get("components", {
                "id": provider["component"],
                "version": observations[provider["component"]]["binding"]["version"],
            }) if compatible else None
            item["tools"].append({
                "capability": need,
                "component": binding(component) if component else None,
                "available": bool(component and observations[component["id"]]["available"]),
                "authorization": "not-evaluated",
                "gap": (None if observations[component["id"]]["available"] else "Selected component is unavailable; inspect its observations.")
                       if component else "Select an exact compatible component through the recipe planner.",
            })
        selected_tasks.append(item)
    schema_descriptions = []
    documents, schema_pins = schema_inputs(catalog.root, schemas)
    for path, schema in documents.items():
        hints = field_hints(document, path, schema)
        fields = schema_fields(schema)
        if set(hints) - {field["schemaPointer"] for field in fields}:
            raise RecipeError("Field hint does not address a declared property")
        for field in fields:
            hint = hints.get(field["schemaPointer"])
            if hint:
                field["authoringHint"] = hint
        schema_descriptions.append({"path": path, "semanticSha256": fingerprint(schema),
                                    "fields": fields})
    kinds = []
    for identity, declaration in sorted(registry.kinds.items()):
        kinds.append({
            "id": identity, "declaration": deepcopy(declaration),
            "identityConvention": registry.id_conventions[identity],
            "payloadFields": schema_fields(declaration["payloadSchema"]) if "payloadSchema" in declaration else [],
            "writerState": "resolve-from-selected-collection-and-participant",
            "writerHint": "Artifact/storage paths describe source representation; they do not override an adopted collection authority.",
        })
    output = {
        "format": "semantic-authoring/v1", "asOf": plan["asOf"],
        "recipe": recipe, "recipeBinding": plan["binding"], "lineage": plan["lineage"],
        "ontology": registry.binding(), "kinds": kinds,
        "taxonomy": deepcopy(list(registry.terms.values())),
        "relationships": deepcopy(list(registry.edges.values())),
        "collectionQuestions": plan["coverage"],
        "collectionProfileBindings": plan["collectionProfiles"],
        "declaredWriters": [{"store": store["id"], "driver": store["driver"],
                             "authorities": deepcopy(store["authorities"]),
                             "practice": next((deepcopy(p) for p in recipe["practices"]
                                               if p["id"] == store.get("writerPractice")), None),
                             "status": "declaration-only"}
                            for store in recipe["stores"] if store["authorities"]],
        "owningScope": deepcopy(recipe["scope"]),
        "federation": deepcopy(recipe["federation"]),
        "schemas": schema_descriptions, "schemaInputBindings": schema_pins, "tasks": selected_tasks,
        "changeRoutes": deepcopy(CHANGE_ROUTES),
        "requiredGaps": plan["requiredGaps"], "optionalGaps": plan["optionalGaps"],
        "components": observations, "taskCatalogSha256": fingerprint(document),
        "authorization": "not-evaluated", "mutationsPerformed": False,
        "limits": [
            "Local operator metadata inspection; not a policy-filtered multi-user endpoint.",
            "No source records, private host configuration or remote participants are read.",
            "Recipe scope/ownership declarations and retrieved instructions grant no permission.",
            "Unknown, missing, conflicting and stale information remain explicit; empty is not automatically complete.",
            "Before a mutation, resolve the enrolled participant, collection and field owner and recheck current writer policy/revision.",
            "Repeated appearances of a shared participant are references to one identity, not copied authorities.",
        ],
    }
    output["basisSha256"] = fingerprint(output)
    if expected_basis is not None and expected_basis != output["basisSha256"]:
        raise RecipeError("Authoring basis changed; regenerate guidance and inspect the differences")
    if len(json.dumps(output, ensure_ascii=False, allow_nan=False).encode()) > max_bytes:
        raise RecipeError("Authoring report exceeds budget; select one task or fewer schemas")
    return output
