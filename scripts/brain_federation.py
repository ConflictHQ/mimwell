"""Explicit federation enrollment and scoped discovery over inventory evidence.

Inventory and manifests are observations, not membership or access grants. The
operator's catalog separates storage, ownership, participation and subject links.
Only host-reviewed subject-link fingerprints become active discovery metadata.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from jsonschema import Draft7Validator

from context_bundle import encode
from context_host import decode
from knowledge_policy import fingerprint

ROOT = Path(__file__).resolve().parents[1]


class FederationError(ValueError):
    pass


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise FederationError("Invalid federation descriptor fields")


def text(value):
    if not isinstance(value, str) or not value.strip():
        raise FederationError("Federation identities and revisions must be explicit")


def strings(values):
    if not isinstance(values, list):
        raise FederationError("Expected a federation identity list")
    for value in values:
        text(value)
    if len(values) != len(set(values)):
        raise FederationError("Duplicate federation identity")


def subject_review_key(participant, link):
    """A review of one brain's facet cannot authorize another brain's assertion."""
    return fingerprint({"participant": participant, "link": link})


class FederationCatalog:
    def __init__(self, document, *, inventory, manifests):
        fields(document, ("protocolVersion", "id", "participants"))
        if (document["protocolVersion"] != "1.0" or not isinstance(inventory, dict)
                or type(inventory.get("version")) is not int or inventory["version"] != 1):
            raise FederationError("Unsupported federation or inventory version")
        text(document["id"])
        if not isinstance(document["participants"], list):
            raise FederationError("Federation participants must be explicit")
        if not isinstance(inventory.get("brains"), list):
            raise FederationError("Invalid federation inventory")
        rows = {}
        for row in inventory["brains"]:
            if not isinstance(row, dict):
                raise FederationError("Invalid inventory location")
            text(row.get("path"))
            if not isinstance(row.get("git"), dict) or not isinstance(row.get("evidence"), dict):
                raise FederationError("Missing inventory storage or manifest evidence")
            if row["path"] in rows:
                raise FederationError("Ambiguous inventory location")
            rows[row["path"]] = row
        validator = Draft7Validator(json.loads((ROOT / "schemas/brain-manifest.schema.json").read_text()))
        participants, stores = {}, {}
        for participant in document["participants"]:
            self._validate(participant)
            identity = participant["id"]
            if identity in participants:
                raise FederationError("Duplicate federation participant")
            location = participant["inventoryPath"]
            observed = rows.get(location)
            raw = manifests.get(location)
            if observed is None or not isinstance(raw, bytes):
                raise FederationError("Participant needs an observed inventory location and manifest")
            expected = participant["manifest"]
            digest = hashlib.sha256(raw).hexdigest()
            evidence = observed["evidence"].get("app/brain-manifest.json")
            if (not isinstance(evidence, dict) or digest != expected["sha256"]
                    or digest != evidence.get("sha256")):
                raise FederationError("Federation manifest pin disagrees with inventory")
            try:
                manifest = decode(raw)
            except ValueError as exc:
                raise FederationError("Invalid federation manifest encoding") from exc
            if list(validator.iter_errors(manifest)) or manifest["identity"]["id"] != expected["identity"]:
                raise FederationError("Invalid or mismatched federation manifest")
            storage = participant["storage"]
            if ("repository" not in observed["git"] or "within_repository" not in observed["git"]
                    or storage["repository"] != observed["git"]["repository"]
                    or storage["component"] != observed["git"]["within_repository"]):
                raise FederationError("Storage identity disagrees with selected inventory location")
            key = (storage["repository"], storage["component"])
            if key[0] is not None:
                if key in stores:
                    raise FederationError("Two participants claim the same repository component; classify clones explicitly")
                stores[key] = identity
            for realm in participant["realms"]:
                if realm["realm"] == "brain" and realm["addressContract"] != manifest["profile"]["contract_version"]:
                    raise FederationError("Brain realm contract disagrees with its manifest")
            participants[identity] = deepcopy(participant)
        # Ownership cannot be cyclic. Membership and peer links may be cyclic;
        # their discovery traversal is bounded and deduplicated instead.
        for identity in participants:
            visited, current = set(), identity
            while current in participants:
                if current in visited:
                    raise FederationError("Cyclic federation ownership")
                visited.add(current)
                current = participants[current]["ownershipParent"]
        self._participants = participants
        self.id = document["id"]

    @staticmethod
    def _validate(item):
        fields(item, ("id", "inventoryPath", "manifest", "storage", "owner", "ownershipParent",
                      "peers", "members", "subjects", "realms"))
        for key in ("id", "inventoryPath", "owner"):
            text(item[key])
        if item["ownershipParent"] is not None:
            text(item["ownershipParent"])
        fields(item["manifest"], ("identity", "sha256"))
        for value in item["manifest"].values():
            text(value)
        if not re.fullmatch(r"[0-9a-f]{64}", item["manifest"]["sha256"]):
            raise FederationError("Manifest pin must be a SHA-256 digest")
        fields(item["storage"], ("repository", "component"))
        for value in item["storage"].values():
            if value is not None:
                text(value)
        for key in ("members", "peers"):
            strings(item[key])
        for key in ("subjects", "realms"):
            if not isinstance(item[key], list):
                raise FederationError("Invalid federation capability or subject list")
        for link in item["subjects"]:
            fields(link, ("subject", "address", "relation", "review"))
            for value in link.values():
                text(value)
            if link["relation"] not in ("same_as", "facet_of", "aligns_with"):
                raise FederationError("Unsupported subject relationship")
        realms = set()
        for realm in item["realms"]:
            fields(realm, ("realm", "authority", "store", "revision", "addressContract",
                           "resolverVersion", "capabilities", "transport", "handle"))
            for key in set(realm) - {"capabilities"}:
                text(realm[key])
            strings(realm["capabilities"])
            if realm["realm"] in realms:
                raise FederationError("Duplicate participant realm")
            realms.add(realm["realm"])
            if realm["store"] not in ("files", "journal", "structured", "code"):
                raise FederationError("Unsupported realm authority class")
            if realm["transport"] not in ("local", "remote", "offline"):
                raise FederationError("Unsupported realm transport class")

    def scoped(self, boundary, *, bindings, reviewed_subjects):
        """Host bindings authorize complete participant descriptor snapshots."""
        if not isinstance(bindings, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                 for k, v in bindings.items()):
            raise FederationError("Invalid discovery resource bindings")
        strings(reviewed_subjects)
        visible = {identity: deepcopy(participant) for identity, participant in self._participants.items()
                   if boundary.permits_resource(bindings.get(fingerprint(participant)), identity)}
        return FederationView(self.id, visible, set(reviewed_subjects), boundary)


class FederationView:
    def __init__(self, identity, participants, reviewed_subjects, boundary):
        self.id = identity
        self._participants = deepcopy(participants)
        self._reviews = frozenset(reviewed_subjects)
        self._authorization = {"principal": boundary.actor, "evaluatedAt": boundary.now}
        self._links = []
        for identity, participant in sorted(participants.items()):
            for relation, targets in (("owned_by", [participant["ownershipParent"]]),
                                      ("peer", participant["peers"]), ("member", participant["members"])):
                for target in sorted(t for t in targets if t in participants):
                    self._links.append({"source": identity, "target": target, "relation": relation})

    @property
    def authorization(self):
        return deepcopy(self._authorization)

    def realm(self, participant, realm):
        """Host-only resolver descriptor; absent and denied participants coincide."""
        descriptor = self._participants.get(participant)
        if descriptor is None:
            return None
        return next((deepcopy(r) for r in descriptor["realms"] if r["realm"] == realm), None)

    def sources(self):
        """Selectable realm coordinates for this boundary (#209); handles stay host-only."""
        return [{"participant": identity, "realm": realm["realm"], "revision": realm["revision"],
                 "capabilities": sorted(realm["capabilities"])}
                for identity, participant in sorted(self._participants.items())
                for realm in sorted(participant["realms"], key=lambda r: r["realm"])]

    def _public(self, identity):
        item = self._participants[identity]
        return {"id": identity, "owner": item["owner"], "storage": deepcopy(item["storage"]),
                "manifest": deepcopy(item["manifest"]),
                "subjects": sorted((deepcopy(link) for link in item["subjects"]
                                    if subject_review_key(identity, link) in self._reviews), key=fingerprint),
                "realms": [{k: deepcopy(v) for k, v in realm.items() if k != "handle"}
                           for realm in sorted(item["realms"], key=lambda r: r["realm"])]}

    def discover(self, roots, *, max_participants, max_depth, max_links, max_bytes):
        strings(roots)
        for value in (max_participants, max_depth, max_links, max_bytes):
            if type(value) is not int or value < 0:
                raise FederationError("Discovery needs explicit nonnegative budgets")
        if max_participants == 0 or max_bytes == 0:
            raise FederationError("Participant and byte budgets must be positive")
        result = {"protocolVersion": "1.0", "federation": self.id,
                  "authorization": deepcopy(self.authorization), "participants": [], "links": [],
                  "unavailable": [], "truncation": []}
        reasons = ["maxBytes", "maxDepth", "maxLinks", "maxParticipants"]

        def fits(candidate):
            return len(encode({**candidate, "truncation": reasons})) <= max_bytes

        def omit(reason):
            if reason not in result["truncation"]:
                result["truncation"].append(reason)
                result["truncation"].sort()

        if not fits(result):
            raise FederationError("Discovery budget cannot hold its envelope")
        queue = deque((identity, 0) for identity in sorted(roots))
        visited, selected = set(), set()
        links = {}
        for link in self._links:
            links.setdefault(link["source"], []).append(link)
        while queue:
            identity, depth = queue.popleft()
            if identity in visited:
                continue
            visited.add(identity)
            if identity not in self._participants:
                candidate = deepcopy(result)
                candidate["unavailable"].append({"participant": identity, "reason": "unavailable"})
                if fits(candidate):
                    result.update(candidate)
                else:
                    omit("maxBytes")
                continue
            if len(selected) >= max_participants:
                omit("maxParticipants")
                continue
            candidate = deepcopy(result)
            candidate["participants"].append(self._public(identity))
            if not fits(candidate):
                omit("maxBytes")
                continue
            result.update(candidate)
            selected.add(identity)
            for link in links.get(identity, []):
                if link["target"] in visited:
                    continue
                if depth >= max_depth:
                    omit("maxDepth")
                else:
                    queue.append((link["target"], depth + 1))
        for link in self._links:
            if link["source"] not in selected or link["target"] not in selected:
                continue
            if len(result["links"]) >= max_links:
                omit("maxLinks")
                break
            candidate = deepcopy(result)
            candidate["links"].append(link)
            if fits(candidate):
                result.update(candidate)
            else:
                omit("maxBytes")
        result["participants"].sort(key=lambda p: p["id"])
        return deepcopy(result)
