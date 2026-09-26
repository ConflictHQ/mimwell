"""Versioned semantic registry shared by compiler, validators and context consumers.

brain-schema.json remains the composed declaration. Legacy declarations without
`registry` retain their old behavior; adoption is explicit and checked, not inferred.
No extension code or external JSON Schema references are executed or fetched.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unicodedata

from jsonschema import Draft202012Validator
from referencing import Registry as SchemaRegistry, Resource

from evidence import validate_record as validate_evidence_record

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_VERSION = "1.0"
SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"


class OntologyError(ValueError):
    pass


def _names(value):
    return value if isinstance(value, list) else [value] if value is not None else []


def _label(value):
    return unicodedata.normalize("NFKC", value).strip().casefold()


def _objects(items, category):
    if not isinstance(items, list):
        raise OntologyError(f"{category}: expected a list")
    result = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
            raise OntologyError(f"{category}: each declaration needs an id")
        if item["id"] in result:
            raise OntologyError(f"{category}: duplicate id {item['id']!r}")
        result[item["id"]] = item
    return result


def _acyclic(links, category):
    visiting, done = set(), set()
    for start in links:
        stack = [(start, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                visiting.remove(node)
                done.add(node)
                continue
            if node in done:
                continue
            if node in visiting:
                raise OntologyError(f"{category}: cycle at {node!r}")
            visiting.add(node)
            stack.append((node, True))
            stack.extend((target, False) for target in reversed(links.get(node, [])))


def _local_schema(value):
    if isinstance(value, dict):
        # Embedded schemas use local definitions only. No network or cross-file
        # resolution is needed to validate an extension's payload.
        for key, child in value.items():
            if key in ("$ref", "$dynamicRef") and (not isinstance(child, str) or not child.startswith("#")):
                raise OntologyError("payloadSchema: only local fragment references are supported")
            if key == "$id":
                raise OntologyError("payloadSchema: nested schema identifiers are not supported")
            _local_schema(child)
    elif isinstance(value, list):
        for child in value:
            _local_schema(child)


class Registry:
    def __init__(self, declaration, schemas=ROOT / "schemas"):
        self.declaration = deepcopy(declaration)
        header = declaration.get("registry")
        if not isinstance(header, dict) or header.get("version") != REGISTRY_VERSION:
            raise OntologyError(f"registry: unsupported version; expected {REGISTRY_VERSION}")
        if not re.fullmatch(SEMVER, str(header.get("ontologyVersion", ""))):
            raise OntologyError("registry: ontologyVersion must be an exact semantic version")
        self.kinds = _objects(declaration.get("kinds"), "kinds")
        self.edges = _objects(declaration.get("edges"), "edges")
        self.terms = _objects(declaration.get("taxonomy", []), "taxonomy")
        self.id_conventions = {}
        for convention, details in (declaration.get("contract") or {}).get("idConventions", {}).items():
            for kid in details.get("kinds", []):
                if kid not in self.kinds or kid in self.id_conventions:
                    raise OntologyError(f"identity convention: unknown or multiply assigned kind {kid!r}")
                self.id_conventions[kid] = convention
        if set(self.kinds) != set(self.id_conventions):
            raise OntologyError("identity convention: every kind needs exactly one convention")
        self.node_schema = json.loads((schemas / "brain-node.schema.json").read_text())
        self.edge_schema = json.loads((schemas / "brain-edge.schema.json").read_text())
        builtins = set(self.node_schema["properties"]["kind"]["enum"])
        self.compiled = {}
        self.payloads = {}
        for kid, kind in self.kinds.items():
            for facet, field in (("kind", "class"), ("mutability", "mutability"), ("source", "source")):
                if kind.get(field) not in (declaration.get("classes") or {}).get(facet, []):
                    raise OntologyError(f"kind {kid}: invalid {field}")
            if "node" not in kind:
                raise OntologyError(f"kind {kid}: explicit node mapping or null required")
            mapped = _names(kind["node"])
            if kind["node"] is not None and (not mapped or not all(isinstance(n, str) and n for n in mapped)):
                raise OntologyError(f"kind {kid}: invalid compiled node mapping")
            for node in mapped:
                self.compiled.setdefault(node, []).append(kid)
                if node not in builtins and (not re.fullmatch(r"[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+", kid)
                                             or "payloadSchema" not in kind):
                    raise OntologyError(f"kind {kid}: extension requires a namespaced id and payloadSchema")
            payload = kind.get("payloadSchema")
            if payload is not None:
                _local_schema(payload)
                try:
                    Draft202012Validator.check_schema(payload)
                except Exception as exc:
                    raise OntologyError(f"kind {kid}: invalid payloadSchema: {exc}") from exc
                self.payloads[kid] = Draft202012Validator(payload)
            adapter = kind.get("adapter")
            if adapter is not None:
                if not isinstance(adapter, dict) or set(adapter) != {"records", "idField", "titleField"}:
                    raise OntologyError(f"kind {kid}: adapter requires records, idField and titleField only")
                if len(mapped) != 1 or not kind.get("artifact") or not all(
                        isinstance(value, str) and value for value in adapter.values()):
                    raise OntologyError(f"kind {kid}: adapter requires one node kind, artifact and field names")
                if self.id_conventions[kid] not in ("slug", "path", "external"):
                    raise OntologyError(f"kind {kid}: unsupported adapter identity convention")
        for node, kinds in self.compiled.items():
            payload_specs = [self.kinds[k].get("payloadSchema") for k in kinds]
            if any(spec != payload_specs[0] for spec in payload_specs):
                raise OntologyError(f"node {node}: conflicting payload mappings from {kinds}")
            prefixes = set()
            for kid in kinds:
                values = self.kinds[kid].get("idPrefixes", [])
                if not isinstance(values, list) or any(not isinstance(p, str) or not re.fullmatch(r"[^/:]+:", p) for p in values):
                    raise OntologyError(f"kind {kid}: invalid idPrefixes")
                if len(kinds) > 1 and (not values or prefixes.intersection(values)):
                    raise OntologyError(f"node {node}: ambiguous mappings need distinct idPrefixes")
                prefixes.update(values)
        for eid, edge in self.edges.items():
            for side in ("domain", "range"):
                values = edge.get(side, [])
                if not isinstance(values, list) or any(not isinstance(k, str) or k not in self.kinds for k in values):
                    raise OntologyError(f"edge {eid}: {side} must name declared semantic kinds")
        self.joins = set((declaration.get("contract") or {}).get("joinEdges", []))
        if self.joins - self.edges.keys():
            raise OntologyError("joinEdges: undeclared relation")
        self.labels = {}
        broader = {}
        for tid, term in self.terms.items():
            if not all(isinstance(term.get(k), str) and term[k].strip() for k in ("scheme", "label", "definition")):
                raise OntologyError(f"term {tid}: scheme, label and definition are required")
            aliases = term.get("aliases", [])
            if not isinstance(aliases, list) or not all(isinstance(a, str) and a.strip() for a in aliases):
                raise OntologyError(f"term {tid}: invalid aliases")
            for label in [term["label"], *aliases]:
                key = (term["scheme"], _label(label))
                if key in self.labels and self.labels[key] != tid:
                    raise OntologyError(f"term {tid}: ambiguous label/alias {label!r}")
                self.labels[key] = tid
            parents = term.get("broader", [])
            if not isinstance(parents, list) or any(not isinstance(p, str) or p not in self.terms for p in parents):
                raise OntologyError(f"term {tid}: broader must name declared terms")
            if any(self.terms[p].get("scheme") != term["scheme"] for p in parents):
                raise OntologyError(f"term {tid}: broader cannot cross schemes")
            broader[tid] = parents
        _acyclic(broader, "taxonomy broader")
        for category, objects in (("kind", self.kinds), ("edge", self.edges), ("term", self.terms)):
            replacements = {}
            for oid, obj in objects.items():
                deprecation = obj.get("deprecated")
                if deprecation is None:
                    continue
                if not isinstance(deprecation, dict) or not re.fullmatch(SEMVER, str(deprecation.get("since", ""))):
                    raise OntologyError(f"{category} {oid}: deprecation requires a semantic since version")
                target = deprecation.get("replacedBy")
                if target is not None and target not in objects:
                    raise OntologyError(f"{category} {oid}: unknown replacement {target!r}")
                replacements[oid] = [target] if target else []
            _acyclic(replacements, f"{category} replacement")
        for name, recipe in declaration.get("contextRecipes", {}).items():
            if name == "$comment":
                continue
            if name != "default" and name not in self.compiled:
                raise OntologyError(f"context recipe {name}: undeclared compiled kind")
            outputs = {"version", "generated_for", "node", "ontology", "evidence_edges"}
            for hop in recipe.get("hops", []):
                output = hop.get("as")
                if not isinstance(output, str) or not output or output in outputs:
                    raise OntologyError(f"context recipe {name}: duplicate or reserved output {output!r}")
                outputs.add(output)
                if hop.get("direction", "out") not in ("in", "out") or any(
                        field in hop and not isinstance(hop[field], bool) for field in ("transitive", "optional")):
                    raise OntologyError(f"context recipe {name}: invalid traversal options")
                if hop.get("rel") not in self.edges and not hop.get("optional", False):
                    raise OntologyError(f"context recipe {name}: undeclared relation {hop.get('rel')!r}")
        self.node_schema["properties"]["kind"]["enum"] = sorted(self.compiled)
        self.edge_schema["required"] = sorted(set(self.edge_schema["required"]) | {"rel"})
        self.edge_schema["properties"]["rel"]["enum"] = sorted(self.edges)
        evidence_schema = json.loads((schemas / "evidence.schema.json").read_text())
        resources = SchemaRegistry().with_resources([
            ("evidence.schema.json", Resource.from_contents(evidence_schema))])
        self.node_validator = Draft202012Validator(self.node_schema, registry=resources)
        self.edge_validator = Draft202012Validator(self.edge_schema, registry=resources)
        envelope = json.loads((schemas / "brain-envelope.schema.json").read_text())
        envelope["properties"]["nodes"]["items"] = self.node_schema
        envelope["properties"]["edges"]["items"] = self.edge_schema
        envelope["properties"]["meta"]["properties"]["version"]["const"] = envelope["x-conflict"]["version"]
        self.envelope_validator = Draft202012Validator(envelope, registry=resources)

    def binding(self):
        """Exact semantic declaration used to interpret an emitted graph."""
        encoded = json.dumps(self.declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return {"registryVersion": REGISTRY_VERSION,
                "ontologyVersion": self.declaration["registry"]["ontologyVersion"],
                "layers": deepcopy(self.declaration["registry"].get("layers", {})),
                "sha256": hashlib.sha256(encoded).hexdigest()}

    def resolve_term(self, text, scheme):
        if text in self.terms and self.terms[text]["scheme"] == scheme:
            return text
        return self.labels.get((scheme, _label(text)))

    def narrower(self, term):
        if term not in self.terms:
            raise OntologyError(f"unknown taxonomy term {term!r}")
        return sorted(tid for tid, value in self.terms.items() if term in value.get("broader", []))

    def validate_records(self, nodes, edges):
        errors = []
        for category, records, validator in (("node", nodes, self.node_validator), ("edge", edges, self.edge_validator)):
            for index, record in enumerate(records):
                for error in validator.iter_errors(record):
                    errors.append(f"{category}[{index}]/{'/'.join(map(str, error.path))}: {error.message}")
                if isinstance(record, dict):
                    try:
                        validate_evidence_record(record)
                    except ValueError as exc:
                        errors.append(f"{category}[{index}]/evidence: {exc}")
                if category == "node" and isinstance(record, dict):
                    if not isinstance(record.get("kind"), str) or not isinstance(record.get("id"), str):
                        continue
                    mapped = self.semantic_kinds(record)
                    if record["kind"] in self.compiled and not mapped:
                        errors.append(f"node[{index}]: identity does not match its declared kind mapping")
                    for kid in mapped:
                        if kid in self.payloads:
                            for error in self.payloads[kid].iter_errors(record.get("data", {})):
                                errors.append(f"node[{index}]/data ({kid}): {error.message}")
        if errors:
            raise OntologyError("\n".join(errors))

    def semantic_kinds(self, node):
        prefix = node["id"].split(":", 1)[0].rsplit("/", 1)[-1] + ":"
        return [kid for kid in self.compiled.get(node["kind"], [])
                if not self.kinds[kid].get("idPrefixes") or prefix in self.kinds[kid]["idPrefixes"]]

    def validate_graph(self, graph, *, require_binding=False):
        errors = [f"graph/{'/'.join(map(str, e.path))}: {e.message}" for e in self.envelope_validator.iter_errors(graph)]
        if errors:
            raise OntologyError("\n".join(errors))
        binding = graph.get("meta", {}).get("ontology")
        if (require_binding or binding is not None) and binding != self.binding():
            raise OntologyError("graph: missing or incompatible ontology binding; recompile or migrate explicitly")
        nodes, edges = graph["nodes"], graph["edges"]
        self.validate_records(nodes, edges)
        by_id = {n["id"]: n for n in nodes}
        if len(by_id) != len(nodes):
            raise OntologyError("graph: duplicate node ids")
        for edge in edges:
            eid = edge["rel"]
            for side, field in (("domain", "source"), ("range", "target")):
                endpoint = by_id.get(edge[field])
                if endpoint is None:
                    if field == "target" and eid in self.joins:
                        continue
                    raise OntologyError(f"edge {eid}: unresolved {field} {edge[field]!r}")
                permitted = self.edges[eid].get(side, [])
                actual = self.semantic_kinds(endpoint)
                if permitted and not set(permitted).intersection(actual):
                    raise OntologyError(f"edge {eid}: {side} rejects {endpoint['kind']}")
        broader = {}
        for edge in edges:
            if edge["rel"] == "broader":
                broader.setdefault(edge["source"], []).append(edge["target"])
        _acyclic(broader, "graph broader")

    def compile_extensions(self, root):
        nodes = []
        for kid, kind in self.kinds.items():
            adapter = kind.get("adapter")
            if adapter is None:
                continue
            relative = Path(kind["artifact"])
            path = root / relative
            if relative.is_absolute() or ".." in relative.parts or any(
                    (root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
                raise OntologyError(f"kind {kid}: adapter artifact must be local and cannot follow symlinks")
            if not path.exists():
                raise OntologyError(f"kind {kid}: missing adapter artifact {relative}")
            data = json.loads(path.read_text())
            rows = data.get(adapter["records"]) if isinstance(data, dict) else None
            if not isinstance(rows, list):
                raise OntologyError(f"kind {kid}: adapter records must be an array")
            seen = set()
            for row in rows:
                identity = row.get(adapter["idField"]) if isinstance(row, dict) else None
                title = row.get(adapter["titleField"]) if isinstance(row, dict) else None
                if not isinstance(identity, str) or not identity.strip() or not isinstance(title, str) or not title.strip():
                    raise OntologyError(f"kind {kid}: each record requires string identity and title")
                convention = self.id_conventions[kid]
                if convention == "slug" and not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity):
                    raise OntologyError(f"kind {kid}: identity must follow its kebab-case slug convention")
                if convention == "path" and (Path(identity).is_absolute() or ".." in Path(identity).parts
                                               or "\\" in identity or Path(identity).as_posix() != identity):
                    raise OntologyError(f"kind {kid}: identity must be a normalized relative POSIX path")
                if identity in seen:
                    raise OntologyError(f"kind {kid}: duplicate adapter identity {identity!r}")
                seen.add(identity)
                nodes.append({"id": f"{kid}:{identity}", "kind": _names(kind["node"])[0],
                              "title": title, "source": relative.as_posix(), "data": row})
        self.validate_records(nodes, [])
        return nodes


def load_registry(root):
    path = Path(root) / "brain-schema.json"
    if not path.exists():
        return None
    try:
        declaration = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise OntologyError(f"cannot load {path}: {exc}") from exc
    if "registry" not in declaration:
        return None
    return Registry(declaration)
