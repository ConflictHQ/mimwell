"""Read-only recipe compatibility observations; no migration or approval executor."""

from copy import deepcopy
import hashlib
from importlib.metadata import version
import json
from pathlib import Path

from brain_recipes import Catalog, fingerprint


class UpgradeError(ValueError):
    pass


DOMAINS = ("recipe", "component", "collectionProfile", "ontologyLayer", "practice",
           "store", "surface", "consumer", "requirement", "kind", "edge", "term",
           "question", "identity", "schema", "axis")
VERSIONED = {"recipe", "component", "collectionProfile", "ontologyLayer", "practice"}
OBLIGATIONS = {
    "recipe": ["review-composition"],
    "component": ["component-conformance", "local-extension-compatibility"],
    "collectionProfile": ["reassess-collection-coverage"],
    "ontologyLayer": ["ontology-mapping", "recompile-context"],
    "practice": ["policy-review", "access-and-mutation-parity"],
    "store": ["authority-inventory", "snapshot-and-restore", "writer-cutover", "post-cutover-recovery"],
    "surface": ["consumer-compatibility", "deep-link-preservation"],
    "consumer": ["competency-questions", "access-parity"],
    "requirement": ["capability-conformance"],
    "kind": ["schema-mapping", "record-validation", "evidence-and-review-preservation"],
    "edge": ["relation-mapping", "endpoint-preservation", "traversal-parity"],
    "term": ["taxonomy-mapping", "aliases-and-classification-parity"],
    "question": ["reassess-collection-coverage", "answer-and-citation-parity"],
    "identity": ["stable-identities-or-explicit-redirects", "incoming-link-and-evidence-preservation"],
    "schema": ["schema-mapping", "record-validation", "consumer-compatibility"],
    "axis": ["review-instance-boundaries"],
}


def _validation_basis():
    root = Path(__file__).resolve().parents[1]
    paths = ["scripts/" + name for name in ("brain_upgrade.py", "brain_recipes.py", "ontology.py",
             "compose-schema.py", "evidence.py")]
    paths += ["schemas/" + name + ".schema.json" for name in
              ("brain-node", "brain-edge", "brain-envelope", "recipe-catalog", "evidence")]
    return {"mode": "trusted-current-core", "runtimeOrInstanceCodeExecuted": False,
            "implementation": {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths},
            "dependencies": {name: version(name) for name in ("jsonschema", "referencing")}}


def _entry(value, *, version=None):
    return {"sha256": fingerprint(value), "version": version, "declaration": deepcopy(value)}


def _file(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise UpgradeError("Observation paths must be relative to their declared root")
    if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise UpgradeError("Observations cannot follow symlinks")
    path = root / path
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def observe(documents, root, reference, *, as_of):
    """Resolve actual declarations/files using trusted core code, not instance code.

    Pins cover selected declarations and implementation files, not the entire
    repository, knowledge corpus or operational state. No runtime is launched.
    """
    root = Path(root)
    catalog = Catalog(documents, root)
    plan = catalog.plan(reference, as_of=as_of)
    recipe = plan["recipe"]
    ontology = catalog.ontology(recipe)
    questions, _ = catalog.questions(recipe, ontology)
    declarations = {domain: {} for domain in DOMAINS}
    for domain, section, refs in (
        ("recipe", "recipes", plan["lineage"]),
        ("component", "components", [c["binding"] for c in plan["components"].values()]),
        ("collectionProfile", "collectionProfiles", recipe["collectionProfiles"]),
    ):
        for ref in refs:
            value = catalog.get(section, ref)
            declarations[domain][value["id"]] = _entry(value, version=value["version"])
    for layer in recipe["ontologyLayers"]:
        path = "profiles/" + layer["id"] + ".json"
        # Catalog already checked local paths; retaining the raw profile catches
        # same-version edits that a composed semantic subset might not expose.
        value = json.loads((root / path).read_text())
        declarations["ontologyLayer"][layer["id"]] = _entry(value, version=layer["version"])
    for domain, key in (("practice", "practices"), ("store", "stores"), ("surface", "surfaces"),
                        ("consumer", "consumers"), ("requirement", "requirements")):
        declarations[domain] = {v["id"]: _entry(v, version=v.get("version")) for v in recipe[key]}
    for domain, rows in (("kind", ontology.kinds), ("edge", ontology.edges), ("term", ontology.terms),
                         ("question", questions)):
        declarations[domain] = {key: _entry(value) for key, value in rows.items()}
    declarations["identity"] = {
        key: _entry({"convention": ontology.id_conventions[key], "node": kind["node"],
                     "prefixes": kind.get("idPrefixes", [])})
        for key, kind in ontology.kinds.items()
    }
    declarations["axis"] = {key: _entry(recipe[key]) for key in
                            ("purpose", "subject", "scope", "runtime", "federation")}
    # Include composed contract defaults and retrieval rules as well as named
    # kinds/edges: a changed traversal contract cannot disappear in a kind diff.
    declarations["axis"]["ontologyContract"] = _entry({
        key: value for key, value in ontology.declaration.items()
        if key not in ("kinds", "edges", "taxonomy")})
    missing_schemas = []
    for name in ("brain-node", "brain-edge", "brain-envelope"):
        path = "schemas/" + name + ".schema.json"
        if _file(root, path) is None:
            missing_schemas.append(path)
        else:
            declarations["schema"][name] = _entry(json.loads((root / path).read_text()))
    files = []
    for identity in sorted(plan["components"]):
        component = declarations["component"][identity]["declaration"]
        for descriptor in sorted(component["implementation"]["files"], key=lambda d: d["path"]):
            actual = _file(root, descriptor["path"])
            files.append({"component": identity, "path": descriptor["path"],
                          "expectedSha256": descriptor["sha256"], "observedSha256": actual,
                          "state": "missing" if actual is None else
                          "matching" if actual == descriptor["sha256"] else "fork-or-drift"})
    result = {
        "protocolVersion": "1.0", "asOf": plan["asOf"],
        "catalogs": [fingerprint(doc) for doc in documents], "recipe": plan["binding"],
        "ontology": plan["ontology"], "declarations": declarations,
        "files": files, "components": plan["components"],
        "requiredGaps": plan["requiredGaps"], "optionalGaps": plan["optionalGaps"],
        "missingSchemas": missing_schemas,
        "validation": _validation_basis(),
        "runtimeVerified": False,
    }
    result["sha256"] = fingerprint(result)
    return result


def _check_observation(value):
    if (not isinstance(value, dict) or value.get("protocolVersion") != "1.0"
            or value.get("sha256") != fingerprint({k: v for k, v in value.items() if k != "sha256"})
            or set(value.get("declarations", {})) != set(DOMAINS)):
        raise UpgradeError("Observation changed or uses an unsupported protocol")


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise UpgradeError("Proposal fields need bounded nonempty text")


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise UpgradeError("Unexpected upgrade proposal fields")


def validate_proposals(proposal, source, target):
    """Proposals are input claims, never proof that mappings or exclusions ran."""
    _keys(proposal, ("protocolVersion", "sourceSha256", "targetSha256", "mappings", "exclusions"))
    if (proposal["protocolVersion"] != "1.0" or proposal["sourceSha256"] != source["sha256"]
            or proposal["targetSha256"] != target["sha256"]):
        raise UpgradeError("Upgrade proposals are stale or refer to different observations")
    sources, targets, excluded = set(), set(), set()
    for key in ("mappings", "exclusions"):
        if not isinstance(proposal[key], list) or len(proposal[key]) > 10000:
            raise UpgradeError("Expected a bounded proposal list")
    for row in proposal["mappings"]:
        _keys(row, ("domain", "source", "target", "adapter", "reason"))
        for key in ("domain", "source", "target", "reason"):
            _text(row[key])
        domain, old, new = row["domain"], row["source"], row["target"]
        if domain not in ("kind", "edge", "term", "identity", "schema", "store", "question"):
            raise UpgradeError("Unsupported mapping domain")
        if old not in source["declarations"][domain] or new not in target["declarations"][domain]:
            raise UpgradeError("Mapping endpoint is not in the observed source/target")
        if (domain, old) in sources or (domain, new) in targets:
            raise UpgradeError("Ambiguous mapping: splits and merges need a separate migration contract")
        _keys(row["adapter"], ("id", "version", "sha256"))
        for value in row["adapter"].values():
            _text(value)
        adapter = target["declarations"]["component"].get(row["adapter"]["id"])
        if adapter is None or row["adapter"] != {
            "id": row["adapter"]["id"], "version": adapter["version"], "sha256": adapter["sha256"]
        }:
            raise UpgradeError("Mapping adapter must pin a selected target component")
        if {"id": "migration.map." + domain, "version": "1.0.0"} not in adapter["declaration"]["provides"]:
            raise UpgradeError("Selected adapter does not declare this mapping capability")
        sources.add((domain, old))
        targets.add((domain, new))
    for row in proposal["exclusions"]:
        _keys(row, ("domain", "id", "reason", "retention"))
        for value in row.values():
            _text(value)
        domain, identity = row["domain"], row["id"]
        if domain not in DOMAINS or identity not in source["declarations"][domain]:
            raise UpgradeError("Exclusion is not in the observed source")
        if identity in target["declarations"][domain]:
            raise UpgradeError("Cannot exclude a declaration still selected by the target")
        if (domain, identity) in excluded or (domain, identity) in sources:
            raise UpgradeError("Duplicate or conflicting exclusion")
        excluded.add((domain, identity))
    return deepcopy(proposal)


def compare(source, target, *, proposals=None):
    """Produce a deterministic compatibility report over two fresh observations."""
    _check_observation(source)
    _check_observation(target)
    if source["asOf"] != target["asOf"]:
        raise UpgradeError("Source and target need the same observation time")
    proposals = validate_proposals(proposals, source, target) if proposals is not None else {
        "protocolVersion": "1.0", "sourceSha256": source["sha256"], "targetSha256": target["sha256"],
        "mappings": [], "exclusions": []}
    mapped = {(r["domain"], r["source"]): r for r in proposals["mappings"]}
    excluded = {(r["domain"], r["id"]): r for r in proposals["exclusions"]}
    changes, unchanged, blockers = [], {domain: 0 for domain in DOMAINS}, []
    for domain in DOMAINS:
        old, new = source["declarations"][domain], target["declarations"][domain]
        for identity in sorted(old.keys() | new.keys()):
            before, after = old.get(identity), new.get(identity)
            if before == after:
                unchanged[domain] += 1
                continue
            state = "added" if before is None else "removed" if after is None else "changed"
            change = {"domain": domain, "id": identity, "state": state,
                      "before": deepcopy(before), "after": deepcopy(after),
                      "obligations": list(OBLIGATIONS[domain]), "disposition": "unresolved"}
            if (domain, identity) in mapped:
                change.update(disposition="mapping-proposed", mapping=deepcopy(mapped[(domain, identity)]))
            elif (domain, identity) in excluded:
                change.update(disposition="exclusion-proposed", exclusion=deepcopy(excluded[(domain, identity)]))
            if (before and after and domain in VERSIONED and before["version"] == after["version"]):
                blockers.append({"reason": "same-version-declaration-changed", "domain": domain, "id": identity})
            changes.append(change)
    for side, observation in (("source", source), ("target", target)):
        for path in observation["missingSchemas"]:
            blockers.append({"reason": "schema-unavailable", "side": side, "path": path})
        for gap in observation["requiredGaps"]:
            blockers.append({"reason": "required-capability-unavailable", "side": side, "gap": deepcopy(gap)})
        for identity, component in sorted(observation["components"].items()):
            if not component["available"]:
                blockers.append({"reason": "selected-component-unavailable", "side": side,
                                 "component": identity, "observation": deepcopy(component)})
    result = {
        "protocolVersion": "1.0", "asOf": source["asOf"],
        "source": deepcopy(source), "target": deepcopy(target),
        "status": "blocked" if blockers else "review-required" if changes or any(
            proposals[key] for key in ("mappings", "exclusions")) else "unchanged",
        "changes": changes, "unchanged": unchanged, "blockers": blockers, "proposals": proposals,
        "identityPolicy": "Preserve record identities by default; convention mappings do not remap existing records.",
        "executionAuthorized": False, "migrationVerified": False,
        "remainingProofs": ["repo-working-database-blob-audit-snapshots", "separate-target-migration",
                            "identity-links-evidence-review-history-preservation", "context-and-access-parity",
                            "final-delta-cutover", "recovery-after-new-writes"],
    }
    result["sha256"] = fingerprint(result)
    return result
