"""Assertion attestations with revisioned source lineage and local locator checks.

No source is fetched, no extractor is executed, and no claim is promoted to truth.
Compiled observations describe the bytes inspected at compile time.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MISSING = object()


class EvidenceError(ValueError):
    pass


def _time(value):
    if value is None:
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError("timezone required")
        return result
    except ValueError as exc:
        raise EvidenceError(f"invalid evidence timestamp: {value}") from exc


def _index(rows, key=lambda r: r["id"]):
    out = {}
    for row in rows:
        identity = key(row)
        if identity in out:
            raise EvidenceError(f"duplicate evidence identity: {identity}")
        out[identity] = row
    return out


def _path(path):
    # Paths also become browser hrefs; disallow encoded/URL traversal as well as filesystem traversal.
    if (not isinstance(path, str) or not path or path.startswith("/") or
            any(p in ("", ".", "..") for p in path.split("/")) or
            any(c in path for c in ("\\", "%", "?", "#", ":")) or
            any(ord(c) < 32 for c in path)):
        raise EvidenceError(f"evidence path must be a plain repository-relative path: {path!r}")
    return Path(path)


def target_key(target):
    if "node" in target:
        return ("node", target["node"])
    edge = target["edge"]
    return ("edge", edge["source"], edge["target"], edge["rel"])


def _pointer(record, path):
    if not path:
        return True  # An empty field addresses the existence of the node/relationship.
    current = record
    if re.search(r"~(?![01])", path):
        raise EvidenceError(f"invalid JSON pointer: {path}")
    for token in path.split("/")[1:]:
        if re.search(r"~(?![01])", token):
            raise EvidenceError(f"invalid JSON pointer: {path}")
        token = token.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list) and not re.fullmatch(r"0|[1-9][0-9]*", token):
                return MISSING
            current = current[int(token)] if isinstance(current, list) else current[token]
        except (KeyError, IndexError, TypeError, ValueError):
            return MISSING
    return current


def _matches(record, assertion):
    value = _pointer(record, assertion["field"])
    return None if value is MISSING else json.dumps(value, sort_keys=True) == json.dumps(assertion["value"], sort_keys=True)


def _href(rep, locator):
    href, kind = quote(rep["path"], safe="/"), locator["kind"]
    if kind == "text":
        return href + "#:~:text=" + quote(locator["quote"], safe="")
    if kind == "code":
        return href + f"#L{locator['startLine']}-L{locator['endLine']}"
    if kind == "page":
        return href + f"#page={locator['page']}"
    if kind == "time":
        return href + f"#t={locator['startMs'] / 1000:g},{locator['endMs'] / 1000:g}"
    region = locator["region"]
    return href + "#xywh=percent:" + ",".join(f"{region[k] * 100:g}" for k in ("x", "y", "width", "height"))


def _support(assertion, attestations, observations):
    support, contradiction = set(), set()
    for attestation in attestations:
        observation = observations[attestation["id"]]
        if (attestation["assertion"] != assertion["id"] or observation["status"] != "available" or
                attestation["review"]["state"] != "reviewed" or assertion["status"] != "active"):
            continue
        if attestation["stance"] == "supports":
            support.update(observation["lineages"])
        elif attestation["stance"] == "contradicts":
            contradiction.update(observation["lineages"])
    return sorted(support), sorted(contradiction)


class Evidence:
    def __init__(self, document, *, partial=False):
        schema = json.loads((ROOT / "schemas/evidence.schema.json").read_text())
        chosen = {"$ref": "#/$defs/bundle", "$defs": schema["$defs"]} if partial else schema
        errors = list(Draft202012Validator(chosen).iter_errors(document))
        if errors:
            raise EvidenceError("\n".join(f"evidence/{'/'.join(map(str, e.path))}: {e.message}" for e in errors))
        self.document = deepcopy(document)
        document = self.document
        self.sources = _index(document["sources"], lambda s: (s["id"], s["revision"]))
        self.representations = _index(document["representations"])
        self.assertions = _index(document["assertions"])
        self.attestations = _index(document["attestations"])
        external = set(document.get("unresolvedAssertions", []))
        if external & self.assertions.keys():
            raise EvidenceError("an unresolved assertion is also present")
        source_identities = {}
        for source in self.sources.values():
            _path(source["path"])
            _time(source["capturedAt"])
            identity = (source["lineage"], source["currentRevision"])
            if source["id"] in source_identities and source_identities[source["id"]] != identity:
                raise EvidenceError("revisions of one original source must share lineage and current revision")
            source_identities[source["id"]] = identity
        self.origins = {}
        visiting = set()

        def origins(identity):
            if identity in visiting:
                raise EvidenceError(f"representation derivation cycle: {identity}")
            if identity in self.origins:
                return self.origins[identity]
            if identity not in self.representations:
                raise EvidenceError(f"unknown parent representation: {identity}")
            rep = self.representations[identity]
            _path(rep["path"])
            _time(rep["extractedAt"])
            visiting.add(identity)
            if bool(rep["origin"]) == bool(rep["derivedFrom"]):
                raise EvidenceError(f"representation {identity} needs either an original source or derivation parents")
            if rep["origin"]:
                key = (rep["origin"]["id"], rep["origin"]["revision"])
                if key not in self.sources:
                    raise EvidenceError(f"unknown original source revision: {key}")
                source = self.sources[key]
                if any(rep[field] != source[field] for field in ("path", "sha256", "modality")):
                    raise EvidenceError(f"original representation {identity} differs from source revision")
                result = {key}
            else:
                result = set().union(*(origins(parent) for parent in rep["derivedFrom"]))
            visiting.remove(identity)
            self.origins[identity] = result
            return result

        for identity in self.representations:
            origins(identity)
        for assertion in self.assertions.values():
            _pointer({}, assertion["field"])
            for relation in ("contradicts", "supersedes", "retracts"):
                for identity in assertion[relation]:
                    if identity == assertion["id"] or identity not in self.assertions and identity not in external:
                        raise EvidenceError(f"assertion {assertion['id']}: invalid {relation} reference {identity}")
        self._check_supersession_cycles()
        for attestation in self.attestations.values():
            if attestation["assertion"] not in self.assertions or attestation["representation"] not in self.representations:
                raise EvidenceError(f"attestation {attestation['id']}: unknown assertion or representation")
            _time(attestation["assertedAt"])
            start, end = map(_time, (attestation["validity"]["from"], attestation["validity"]["until"]))
            if start is not None and end is not None and start > end:
                raise EvidenceError("validity interval is reversed")
            review = attestation["review"]
            _time(review["at"])
            if review["state"] in ("reviewed", "retracted") and not all(review[k] for k in ("by", "at", "reason")):
                raise EvidenceError("a completed review requires identity, time and reason")
            self._locator(attestation)
        if partial:
            observations = _index(document["observations"], lambda o: o["attestation"])
            claims = _index(document["claims"], lambda c: c["assertion"])
            if observations.keys() != self.attestations.keys() or claims.keys() != self.assertions.keys():
                raise EvidenceError("compiled evidence observations do not cover exactly the declared assertions/attestations")
            for identity, observation in observations.items():
                if observation["lineages"] != self.lineages(self.attestations[identity]["representation"]):
                    raise EvidenceError("compiled evidence lineage disagrees with original sources")
                attestation = self.attestations[identity]
                rep = self.representations[attestation["representation"]]
                if observation["href"] != _href(rep, attestation["locator"]):
                    raise EvidenceError("compiled citation does not match the representation locator")
            for identity, claim in claims.items():
                support, contradiction = _support(self.assertions[identity], self.attestations.values(), observations)
                if claim["supportingLineages"] != support or claim["contradictingLineages"] != contradiction:
                    raise EvidenceError("compiled support counts disagree with attestations")

    def _check_supersession_cycles(self):
        visiting, done = set(), set()

        def walk(identity):
            if identity in visiting:
                raise EvidenceError("assertion supersession cycle")
            if identity in done or identity not in self.assertions:
                return
            visiting.add(identity)
            for parent in self.assertions[identity]["supersedes"]:
                walk(parent)
            visiting.remove(identity)
            done.add(identity)
        for identity in self.assertions:
            walk(identity)

    def _locator(self, attestation):
        locator = attestation["locator"]
        modality = self.representations[attestation["representation"]]["modality"]
        permitted = {"text": {"text"}, "code": {"code"}, "page": {"document"},
                     "image": {"image"}, "time": {"audio", "video"}}
        if modality not in permitted[locator["kind"]]:
            raise EvidenceError("locator kind does not match representation modality")
        if locator["kind"] == "text" and locator["end"] <= locator["start"]:
            raise EvidenceError("text locator requires a nonempty forward range")
        if locator["kind"] == "code" and locator["endLine"] < locator["startLine"]:
            raise EvidenceError("code line range is reversed")
        if locator["kind"] == "time" and locator["endMs"] <= locator["startMs"]:
            raise EvidenceError("time range is reversed")
        region = locator.get("region")
        if region and (region["width"] <= 0 or region["height"] <= 0 or
                       region["x"] + region["width"] > 1 or region["y"] + region["height"] > 1):
            raise EvidenceError("region must fit inside the normalized image/page")

    def lineages(self, representation):
        return sorted({self.sources[key]["lineage"] for key in self.origins[representation]})

    def ancestors(self, identity):
        result = {identity}
        for parent in self.representations[identity]["derivedFrom"]:
            result.update(self.ancestors(parent))
        return result

    def observe(self, root, attestation):
        root = Path(root)
        rep = self.representations[attestation["representation"]]
        reasons, status = [], "available"
        priority = {"available": 0, "unknown": 1, "stale": 2, "missing": 3}

        def report(level, reason):
            nonlocal status
            if priority[level] > priority[status]:
                status = level
            reasons.append(reason)

        payloads = {}
        for identity in sorted(self.ancestors(rep["id"])):
            item = self.representations[identity]
            relative = _path(item["path"])
            if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
                raise EvidenceError(f"evidence cannot follow symlinks: {item['path']}")
            try:
                content = (root / relative).read_bytes()
                payloads[identity] = content
            except FileNotFoundError:
                report("missing", f"missing representation: {identity}")
                continue
            if item["sha256"] is None:
                report("unknown", f"unknown content fingerprint: {identity}")
            elif hashlib.sha256(content).hexdigest() != item["sha256"]:
                report("stale", f"content fingerprint changed: {identity}")
        for key in sorted(self.origins[rep["id"]], key=str):
            source = self.sources[key]
            if source["revision"] is None or source["currentRevision"] is None:
                report("unknown", f"unknown current source revision: {source['id']}")
            elif source["revision"] != source["currentRevision"]:
                report("stale", f"source revision changed: {source['id']}")
        locator = attestation["locator"]
        kind = locator["kind"]
        href, verification = _href(rep, locator), "anchor-only"
        if kind == "code":
            if any(key[1] != locator["commit"] for key in self.origins[rep["id"]]):
                report("stale", "code commit does not match source revision")
        if status == "available" and kind in ("text", "code"):
            try:
                content = payloads[rep["id"]].decode("utf-8")
                if kind == "text":
                    valid = content[locator["start"]:locator["end"]] == locator["quote"]
                    valid = valid and locator["end"] <= len(content)
                    verification = "exact-text"
                else:
                    valid = locator["endLine"] <= len(content.splitlines())
                    verification = "line-range"
                if not valid:
                    report("stale", "locator does not resolve against pinned content")
            except UnicodeDecodeError:
                report("stale", "text/code representation is not UTF-8")
        if status != "available":
            verification = "unavailable"
        return {"attestation": attestation["id"], "status": status, "reasons": reasons,
                "href": href, "locatorVerification": verification, "lineages": self.lineages(rep["id"])}

    def bundle(self, root, assertions, record):
        selected = {a["id"] for a in assertions}
        attestations = [a for a in self.attestations.values() if a["assertion"] in selected]
        # A public claim must not reveal a link to a private contradicting or
        # superseded claim. Carry the linked evidence paths so the existing
        # deny-biased record filter inherits those source restrictions too.
        related, pending = set(selected), list(selected)
        while pending:
            assertion = self.assertions[pending.pop()]
            for relation in ("contradicts", "supersedes", "retracts"):
                for identity in assertion[relation]:
                    if identity not in related and identity in self.assertions:
                        related.add(identity)
                        pending.append(identity)
        related_attestations = [a for a in self.attestations.values() if a["assertion"] in related]
        representations = set().union(*(self.ancestors(a["representation"]) for a in related_attestations))
        sources = set().union(*(self.origins[r] for r in representations))
        observations = [self.observe(root, a) for a in sorted(attestations, key=lambda a: a["id"])]
        by_attestation = {o["attestation"]: o for o in observations}
        claims = []
        for assertion in sorted(assertions, key=lambda a: a["id"]):
            support, contradiction = _support(assertion, attestations, by_attestation)
            claims.append({"assertion": assertion["id"], "matchesRecord": _matches(record, assertion),
                           "supportingLineages": support, "contradictingLineages": contradiction})
        links = {identity for a in assertions for relation in ("contradicts", "supersedes", "retracts") for identity in a[relation]}
        return deepcopy({"protocolVersion": "1.0", "sources": [self.sources[k] for k in sorted(sources, key=str)],
                "representations": [self.representations[k] for k in sorted(representations)],
                "assertions": sorted(assertions, key=lambda a: a["id"]),
                "attestations": sorted(attestations, key=lambda a: a["id"]),
                "unresolvedAssertions": sorted(links - selected), "observations": observations, "claims": claims})


def compile_evidence(root, nodes, edges):
    path = Path(root) / "app/evidence.json"
    if not path.exists():
        return
    if path.is_symlink():
        raise EvidenceError("evidence catalog cannot be a symlink")
    evidence = Evidence(json.loads(path.read_text()))
    targets = {("node", n["id"]): n for n in nodes}
    targets.update({("edge", e["source"], e["target"], e["rel"]): e for e in edges})
    grouped = {}
    for assertion in evidence.assertions.values():
        key = target_key(assertion["target"])
        if key not in targets:
            raise EvidenceError(f"assertion {assertion['id']}: target was not compiled: {key}")
        grouped.setdefault(key, []).append(assertion)
    for key, assertions in grouped.items():
        targets[key]["evidence"] = evidence.bundle(root, assertions, targets[key])


def validate_record(record):
    if "evidence" not in record:
        return
    evidence = Evidence(record["evidence"], partial=True)
    actual = ("node", record["id"]) if "id" in record else ("edge", record["source"], record["target"], record["rel"])
    if any(target_key(a["target"]) != actual for a in evidence.assertions.values()):
        raise EvidenceError("compiled assertion is attached to the wrong record")
    for claim in record["evidence"]["claims"]:
        if claim["matchesRecord"] is not _matches(record, evidence.assertions[claim["assertion"]]):
            raise EvidenceError("compiled claim comparison disagrees with record")
