"""Inspect declared component inputs and outputs without running component code.

Interface validation is deliberately separate from runtime acceptance, packaging,
permission and reuse rights. Source and schema pins make stale reviews visible.
"""

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
from urllib.parse import unquote, urldefrag, urlsplit

from brain_recipes import RecipeError, ROOT, _safe_file, fingerprint
from component_discovery import local_json, validate_json, validate_schema

MAX_BYTES = 4 * 1024 * 1024
MAX_SCHEMAS = 32
MAX_VALUES = 100000
SCHEMA_MAPS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
SCHEMA_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
SCHEMA_CHILDREN = {"items", "contains", "additionalProperties", "unevaluatedProperties",
                   "unevaluatedItems", "propertyNames", "not", "if", "then", "else"}


def validate_reference_targets(schema):
    """Resolve document-local pointers even when no observed value was supplied."""
    visited = set()

    def walk(node, *, top=False):
        if not isinstance(node, dict):
            return
        if id(node) in visited:
            return
        visited.add(id(node))
        if any(key in node for key in ("$anchor", "$dynamicAnchor", "$dynamicRef")) or (not top and "$id" in node):
            raise RecipeError("Dynamic/named anchors or nested schema identities are unsupported")
        if "$ref" in node:
            reference = node["$ref"]
            if not isinstance(reference, str) or not reference.startswith("#"):
                raise RecipeError("Interface schemas cannot retrieve external references")
            pointer = unquote(reference[1:])
            if pointer and not pointer.startswith("/"):
                raise RecipeError("Named schema anchors are unsupported")
            target = schema
            try:
                for part in pointer.split("/")[1:]:
                    part = part.replace("~1", "/").replace("~0", "~")
                    if isinstance(target, list):
                        if not re.fullmatch(r"0|[1-9][0-9]*", part):
                            raise KeyError(part)
                        target = target[int(part)]
                    else:
                        target = target[part]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise RecipeError("Unresolvable interface schema pointer") from exc
            if not isinstance(target, (dict, bool)):
                raise RecipeError("Interface schema pointer does not identify a schema")
            walk(target)
        for key, value in node.items():
            if key in SCHEMA_MAPS and isinstance(value, dict):
                for child in value.values():
                    walk(child)
            elif key in SCHEMA_LISTS and isinstance(value, list):
                for child in value:
                    walk(child)
            elif key in SCHEMA_CHILDREN:
                walk(value)
    walk(schema, top=True)


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RecipeError("Duplicate interface JSON member")
            result[key] = value
        return result

    def reject(value):
        raise RecipeError("Non-finite interface JSON number")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            reject(value)
        return number

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject, parse_float=finite)


def observed_values(inputs, outputs):
    values = {"inputs": {} if inputs is None else inputs, "outputs": {} if outputs is None else outputs}
    if any(not isinstance(value, dict) for value in values.values()):
        raise RecipeError("Observed input/output values must be maps")

    remaining_bytes, remaining_values = MAX_BYTES, MAX_VALUES

    def charge(size):
        nonlocal remaining_bytes
        remaining_bytes -= size
        if remaining_bytes < 0:
            raise RecipeError("Observed values exceed their byte limit")

    def check(value, depth=0):
        nonlocal remaining_values
        remaining_values -= 1
        if remaining_values < 0:
            raise RecipeError("Observed values exceed their value-count limit")
        if depth > 128:
            raise RecipeError("Observed values exceed their nesting limit")
        if isinstance(value, dict):
            if len(value) * 2 > remaining_values:
                raise RecipeError("Observed values exceed their value-count limit")
            charge(2 + max(0, len(value) - 1) * 2 + len(value) * 2)
            for key, child in value.items():
                if not isinstance(key, str):
                    raise RecipeError("Observed JSON member names must be strings")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > remaining_values:
                raise RecipeError("Observed values exceed their value-count limit")
            charge(2 + max(0, len(value) - 1) * 2)
            for child in value:
                check(child, depth + 1)
        elif type(value) is str:
            charge(len(value) + 2)
            for character in value:
                code = ord(character)
                if character in '\\"\b\f\n\r\t':
                    charge(1)
                elif code < 32:
                    charge(5)
                elif 0xD800 <= code <= 0xDFFF:
                    raise RecipeError("Observed strings must be valid UTF-8")
                elif code > 0xFFFF:
                    charge(3)
                elif code > 0x7FF:
                    charge(2)
                elif code > 0x7F:
                    charge(1)
        elif type(value) is int:
            if value.bit_length() > remaining_bytes * 4:
                raise RecipeError("Observed number exceeds its byte limit")
            charge(len(str(value)))
        elif type(value) is float:
            if not math.isfinite(value):
                raise RecipeError("Observed values are not finite JSON")
            charge(len(repr(value)))
        elif value is None:
            charge(4)
        elif type(value) is bool:
            charge(4 if value else 5)
        elif type(value) not in (str, int, float, bool, type(None)):
            raise RecipeError("Observed values must use JSON types")

    check(values)
    try:
        raw = json.dumps(values, ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise RecipeError("Observed values are not finite JSON") from exc
    if len(raw) > MAX_BYTES:
        raise RecipeError("Observed values exceed their byte limit")
    return parse_json(raw)


def pinned_bytes(root, descriptor, *, max_bytes=MAX_BYTES):
    root = Path(root)
    if root.is_symlink() or not _safe_file(root, descriptor["path"]):
        raise RecipeError("Pinned interface source is unavailable")
    with (root / descriptor["path"]).open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
        raise RecipeError("Pinned interface source is changed or exceeds its limit")
    return raw


def contract_schema(root, contract):
    """Bundle only explicitly pinned local schemas; never retrieve a reference.

    Local JSON pointers remain relative to their original schema document.
    Remote references, nested resource identities and dynamic references refuse.
    """
    if contract["schema"] is not None:
        schema = deepcopy(contract["schema"])
        validate_schema(schema)
        validate_reference_targets(schema)
        return schema
    pins = contract["schemaFiles"]
    if not 1 <= len(pins) <= MAX_SCHEMAS:
        raise RecipeError("Interface schema closure must contain 1 to 32 files")
    names = {pin["path"]: f"s{i}" for i, pin in enumerate(pins)}
    if len(names) != len(pins):
        raise RecipeError("Duplicate interface schema path")
    documents = {}
    total = 0
    for pin in pins:
        raw = pinned_bytes(root, pin, max_bytes=MAX_BYTES - total)
        total += len(raw)
        if total > MAX_BYTES:
            raise RecipeError("Interface schema closure exceeds its byte limit")
        documents[pin["path"]] = parse_json(raw)

    def rewrite(value, path, *, top=False):
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "$id":
                if not top:
                    raise RecipeError("Nested schema identities are unsupported")
                continue
            if key in ("$dynamicRef", "$dynamicAnchor", "$anchor"):
                raise RecipeError("Dynamic or named schema anchors are unsupported")
            if key == "$ref":
                target, fragment = urldefrag(item)
                url = urlsplit(target)
                if url.scheme or url.netloc or url.query or target.startswith("/"):
                    raise RecipeError("Interface schemas cannot retrieve external references")
                if target:
                    parts = (*PurePosixPath(path).parent.parts, *PurePosixPath(target).parts)
                    if ".." in parts or "\\" in target:
                        raise RecipeError("Interface schema reference escapes its declared closure")
                    destination = str(PurePosixPath(*parts))
                else:
                    destination = path
                if destination not in names or (fragment and not fragment.startswith("/")):
                    raise RecipeError("Interface schema reference is not in its pinned closure")
                result[key] = "#/$defs/" + names[destination] + fragment
            elif key in SCHEMA_MAPS and isinstance(item, dict):
                result[key] = {name: rewrite(child, path) for name, child in item.items()}
            elif key in SCHEMA_LISTS and isinstance(item, list):
                result[key] = [rewrite(child, path) for child in item]
            elif key in SCHEMA_CHILDREN:
                result[key] = rewrite(item, path)
            else:
                result[key] = deepcopy(item)
        return result

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {names[path]: rewrite(value, path, top=True) for path, value in documents.items()},
        "$ref": "#/$defs/s0" + contract["pointer"],
    }
    validate_schema(schema)
    validate_reference_targets(schema)
    return schema


def _version_key(value, *, canonical=True):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise RecipeError("Interface versions must use numeric major.minor.patch")
    if canonical and any(str(int(part)) != part for part in value.split(".")):
        raise RecipeError("Protocol 1.1 versions must use canonical numeric components")
    return tuple(int(part) for part in value.split("."))


class Interfaces:
    def __init__(self, discovery, document, *, root=ROOT):
        self.discovery = discovery
        self.root = Path(root)
        validate_json(document, local_json(ROOT, "schemas/component-interfaces.schema.json"))
        self.document = deepcopy(document)
        protocol = self.document.get("protocolVersion")
        self.protocol_version = protocol
        self.history = {}
        self.discovery_versions = {}
        current = {}
        for item in discovery.document["entries"]:
            if protocol == "1.1":
                _version_key(item["version"])
            key = (item["id"], item["version"])
            if key in current:
                raise RecipeError("Duplicate discovery identity and version")
            current[key] = item
        latest_discovery = {}
        for item in current.values():
            previous = latest_discovery.get(item["id"])
            if protocol == "1.0" or previous is None or _version_key(item["version"]) > _version_key(previous["version"]):
                latest_discovery[item["id"]] = item
        for entry in self.document["entries"]:
            if protocol == "1.1":
                _version_key(entry["version"])
                if "discoveryVersion" in entry:
                    _version_key(entry["discoveryVersion"])
            identity_version = (entry["id"], entry["version"])
            if identity_version in self.history:
                raise RecipeError("Duplicate component interface identity and version")
            if protocol == "1.0":
                # Preserve the original protocol's unique-ID/current-discovery contract.
                if "discoveryVersion" in entry:
                    raise RecipeError("Protocol 1.0 does not support exact discovery versions")
                if any(identity == entry["id"] for identity, _ in self.history):
                    raise RecipeError("Duplicate component interface identity")
                source = latest_discovery.get(entry["id"])
                if source is None or fingerprint(source) != entry["discoverySha256"]:
                    raise RecipeError("Interface review disagrees with the discovery entry")
            else:
                candidates = [item for (identity, _), item in current.items() if identity == entry["id"]]
                if "discoveryVersion" in entry:
                    source = current.get((entry["id"], entry["discoveryVersion"]))
                    if source is None or fingerprint(source) != entry["discoverySha256"]:
                        raise RecipeError("Interface review disagrees with its exact discovery version")
                else:
                    matches = [item for item in candidates if fingerprint(item) == entry["discoverySha256"]]
                    if len(matches) != 1:
                        raise RecipeError("Historical interface discovery binding is missing or ambiguous")
                    source = matches[0]
            if source is None:
                raise RecipeError("Interface review disagrees with the discovery entry")
            self.discovery_versions[identity_version] = source["version"]
            for direction in ("inputs", "outputs"):
                ports = entry[direction]
                if len({port["id"] for port in ports}) != len(ports):
                    raise RecipeError("Duplicate component interface port")
            self.history[identity_version] = entry
        self.entries = {}
        for identity, version in self.history:
            previous = self.entries.get(identity)
            if (protocol == "1.0" or previous is None
                    or _version_key(version) > _version_key(previous["version"])):
                self.entries[identity] = self.history[(identity, version)]
        requests = self.document.get("consumerRequests", [])
        if len({request["id"] for request in requests}) != len(requests):
            raise RecipeError("Duplicate consumer request identity")
        if any(set(request["relatedComponents"]) - set(self.entries) for request in requests):
            raise RecipeError("Consumer request refers to an unreviewed component")

    def coverage(self):
        """Report review coverage, retaining absent and proposed capabilities.

        Coverage means a review exists for the discovery identity. It is not a
        count of installed or accepted components; no observed values are read.
        """
        current = {}
        for item in self.discovery.document["entries"]:
            previous = current.get(item["id"])
            if (self.protocol_version == "1.0" or previous is None
                    or _version_key(item["version"]) > _version_key(previous["version"])):
                current[item["id"]] = item
        entries = []
        for identity in sorted(self.entries):
            declaration = self.entries[identity]
            inspection = self.inspect(identity)
            item = {
                "id": identity, "title": current[identity]["title"],
                "disposition": inspection["disposition"],
                "sourceReviewCurrent": inspection["sourceReviewCurrent"],
                "externalSourceCount": len(declaration.get("externalSources", [])),
                "externalSourcesRechecked": False,
                "inputs": [{"id": port["id"], "meaning": port["meaning"], "required": port["required"]}
                           for port in declaration["inputs"]],
                "outputs": [{"id": port["id"], "meaning": port["meaning"], "required": port["required"]}
                            for port in declaration["outputs"]],
                "schemasAvailable": all(port["state"] != "unavailable-or-invalid"
                                        for direction in ("inputs", "outputs") for port in inspection[direction]),
                "review": declaration["review"], "limits": declaration["limits"],
                "gapIssues": declaration["gapIssues"],
            }
            if self.protocol_version == "1.1":
                item["reviewVersion"] = declaration["version"]
                item["discoveryVersion"] = self.discovery_versions[(identity, declaration["version"])]
                item["discoverySha256"] = declaration["discoverySha256"]
            entries.append(item)
        missing = sorted(set(current) - set(self.entries))
        return {
            "protocolVersion": self.protocol_version, "discoveryEntries": len(current),
            "reviewEntries": len(entries), "missingReviews": missing,
            "reviewCoverageComplete": not missing,
            "runtimeVerified": False, "authorizationVerified": False, "redistributionGranted": False,
            "entries": entries, "consumerRequests": deepcopy(self.document.get("consumerRequests", [])),
        }

    def inspect(self, identity, *, version=None, inputs=None, outputs=None):
        if not isinstance(identity, str):
            raise RecipeError("No reviewed interface for that component")
        if version is not None:
            entry = self.history.get((identity, version))
        else:
            entry = self.entries.get(identity)
        if entry is None:
            raise RecipeError("No reviewed interface for that component version")
        values_by_direction = observed_values(inputs, outputs)
        report = {
            "protocolVersion": self.protocol_version, "id": identity, "version": entry["version"],
            "basis": fingerprint(entry), "disposition": entry["disposition"],
            "sourceReviewCurrent": True if entry["sourcePins"] else None, "inputs": [], "outputs": [],
            "runtimeVerified": False, "authorizationVerified": False,
            "redistributionGranted": False, "implementationAvailable": None,
            "externalSourceCount": len(entry.get("externalSources", [])), "externalSourcesRechecked": False,
            "limits": entry["limits"], "gapIssues": entry["gapIssues"],
        }
        if self.protocol_version == "1.1":
            report["discoveryVersion"] = self.discovery_versions[(identity, entry["version"])]
            report["discoverySha256"] = entry["discoverySha256"]
        for pin in entry["sourcePins"]:
            try:
                pinned_bytes(self.root, pin)
            except (ValueError, OSError):
                report["sourceReviewCurrent"] = False
        for direction, values in values_by_direction.items():
            ports = entry[direction]
            if set(values) - {port["id"] for port in ports}:
                raise RecipeError("Undeclared component interface port")
            for port in ports:
                item = {"id": port["id"], "required": port["required"], "state": "not-inspected", "valueSha256": None}
                try:
                    schema = contract_schema(self.root, port)
                    item["contractSha256"] = fingerprint(schema)
                    if port["id"] in values:
                        value = values[port["id"]]
                        validate_json(value, schema)
                        item.update(state="valid", valueSha256=fingerprint(value))
                except (ValueError, OSError, KeyError, TypeError, RecursionError):
                    item["state"] = "unavailable-or-invalid"
                report[direction].append(item)
            report[direction + "Valid"] = bool(ports) and all(
                item["state"] != "unavailable-or-invalid" and (not item["required"] or item["state"] == "valid")
                for item in report[direction]
            )
        report["observedValuesConform"] = (entry["disposition"] != "proposed" and
                                          report["sourceReviewCurrent"] is True and
                                          report["inputsValid"] and report["outputsValid"])
        return report
