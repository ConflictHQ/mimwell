"""Pinned practice inheritance and mutation authorization; imported content has no grants.

The caller supplies authenticated identity, observed revision, time and verified
approval identities through `trusted`. Never populate that context from a request.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
ACL = ("readers", "proposers", "committers", "reviewers")
RULES = (*ACL, "fastAuto", "separateReview", "allowDelete", "retentionDays")


class PolicyError(ValueError):
    pass


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def timestamp(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})", value):
            raise ValueError("ISO timestamp required")
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timezone required")
        return parsed
    except (ValueError, TypeError, AttributeError) as exc:
        raise PolicyError("a timezone-aware policy timestamp is required") from exc


def validate(document, name):
    schema = json.loads((ROOT / "schemas" / (name + ".schema.json")).read_text())
    errors = list(Draft202012Validator(schema).iter_errors(document))
    if errors:
        raise PolicyError("; ".join(f"/{'/'.join(map(str, e.path))}: {e.message}" for e in errors))


def indexed(rows, field="id"):
    result = {}
    for row in rows:
        if row[field] in result:
            raise PolicyError(f"duplicate policy identity: {row[field]}")
        result[row[field]] = row
    return result


def local_path(value):
    if not value or value.startswith("/") or any(p in ("", ".", "..") for p in value.split("/")) or any(c in value for c in "\\:%?#"):
        raise PolicyError("policy sources must use plain relative paths")
    return Path(value)


class Policy:
    def __init__(self, document, ontology):
        validate(document, "knowledge-policy")
        self.document = deepcopy(document)
        document = self.document
        self.binding = {"id": document["id"], "version": document["version"], "sha256": fingerprint(document),
                        "ontologySha256": fingerprint(ontology)}
        self.principals = indexed(document["principals"])
        self.scopes = indexed(document["scopes"])
        self.resources = indexed(document["resources"])
        self.exceptions = indexed(document["exceptions"], "scope")
        self.kinds = {k["id"]: k["mutability"] for k in ontology["kinds"]}
        if any(tier not in ("fast", "slow", "anchor") for tier in self.kinds.values()):
            raise PolicyError("unsupported ontology mutability")
        for scope in self.scopes.values():
            local_path(scope["practice"]["path"])
            if scope["owner"] not in self.principals:
                raise PolicyError("scope owner is not a declared principal")
            if scope["parent"] is None and set(scope["rules"]) != set(RULES):
                raise PolicyError("root scope must declare every rule")
            for key in ACL:
                if set(scope["rules"].get(key, [])) - self.principals.keys():
                    raise PolicyError("policy grant names an unknown principal")
            seen, current = set(), scope
            while current["parent"] is not None:
                if current["id"] in seen or current["parent"] not in self.scopes:
                    raise PolicyError("scope inheritance cycle or unknown parent")
                seen.add(current["id"])
                current = self.scopes[current["parent"]]
        for resource in self.resources.values():
            if resource["scope"] not in self.scopes or resource["kind"] not in self.kinds:
                raise PolicyError("resource names an unknown scope or ontology kind")
            if resource["retentionSince"] is not None:
                timestamp(resource["retentionSince"])
        for exception in self.exceptions.values():
            if exception["scope"] not in self.scopes or exception["approvedBy"] not in self.principals:
                raise PolicyError("exception names an unknown scope or approver")
            timestamp(exception["expiresAt"])

    def effective(self, scope_id, now):
        scope = self.scopes[scope_id]
        if scope["parent"] is None:
            return deepcopy(scope["rules"]), [scope["practice"]], []
        inherited, chain, exceptions = self.effective(scope["parent"], now)
        changes = scope["rules"]
        relaxes = any(not set(changes[k]).issubset(inherited[k]) for k in ACL if k in changes)
        relaxes |= any(changes.get(k, inherited[k]) and not inherited[k] for k in ("fastAuto", "allowDelete"))
        relaxes |= inherited["separateReview"] and not changes.get("separateReview", inherited["separateReview"])
        relaxes |= changes.get("retentionDays", inherited["retentionDays"]) < inherited["retentionDays"]
        if relaxes:
            exception = self.exceptions.get(scope_id)
            if (not exception or exception["approvedBy"] not in inherited["reviewers"] or
                    now >= timestamp(exception["expiresAt"])):
                raise PolicyError("scope relaxation needs a current exception approved by an inherited reviewer")
            exceptions.append(deepcopy(exception))
        inherited.update(deepcopy(changes))
        return inherited, [*chain, scope["practice"]], exceptions

    def evaluate(self, request, trusted):
        validate(request, "mutation-request")
        result = {"allowed": False, "requiresReview": False, "reasons": [], "policy": deepcopy(self.binding),
                  "resource": request["resource"], "practiceChain": [], "exceptions": [], "reviewers": []}

        def deny(reason):
            result["reasons"].append(reason)
            return result

        actor, operation = trusted["actor"], trusted["operation"]
        if actor not in self.principals or operation not in ("read", "propose", "review", "commit"):
            return deny("unknown actor or operation")
        resource = self.resources.get(request["resource"])
        if resource is None:
            return deny("resource is outside this policy")
        now = timestamp(trusted["now"])
        try:
            rules, chain, exceptions = self.effective(resource["scope"], now)
        except PolicyError as exc:
            return deny(str(exc))
        result.update({"practiceChain": chain, "exceptions": exceptions})
        if actor not in rules["readers"]:
            return deny("read access denied")
        if operation == "read":
            result["allowed"] = True
            return result
        tier = self.kinds[resource["kind"]]
        if tier == "anchor":
            return deny("anchor knowledge cannot be mutated through this gate")
        if request["mutation"] == "read":
            return deny("a write operation requires a mutation")
        if request["expectedRevision"] != trusted["currentRevision"]:
            return deny("stale revision; propose again against the current record")
        if not request["evidence"] or not request["reason"].strip():
            return deny("mutation requires reason and evidence")
        permission = {"propose": "proposers", "review": "reviewers", "commit": "committers"}[operation]
        if actor not in rules[permission]:
            return deny(f"{operation} authority denied")
        if request["mutation"] == "delete":
            since = trusted.get("retentionSince", resource["retentionSince"])
            if not rules["allowDelete"] or since is None:
                return deny("deletion is forbidden or retention age is unknown")
            if (now - timestamp(since)).total_seconds() < rules["retentionDays"] * 86400:
                return deny("retention period has not elapsed")
        if request["mutation"] == "promote":
            source = self.resources.get(request["sourceResource"])
            if source is None:
                return deny("promotion requires a governed source resource")
            try:
                source_rules, _, _ = self.effective(source["scope"], now)
            except PolicyError:
                return deny("source policy is unavailable")
            if actor not in source_rules["readers"]:
                return deny("promotion source read access denied")
            if operation == "commit" and trusted.get("sourceApprovedBy") not in source_rules["reviewers"]:
                return deny("promotion requires source-scope release approval")
        elif request["sourceResource"] is not None:
            return deny("sourceResource is only valid for promotion")
        owner = self.scopes[resource["scope"]]["owner"]
        needs_review = (tier != "fast" or not rules["fastAuto"] or trusted.get("proposedBy", actor) != owner or
                        request["mutation"] in ("supersede", "retract", "delete", "promote"))
        # Only a trusted app host supplies this after validating an owned grant.
        # A service-owned fast scope may retract its own app data; no review or
        # approval identity is fabricated and shared/slow knowledge stays governed.
        app_owner = trusted.get("appPrincipal")
        if (app_owner == owner == trusted.get("proposedBy", actor)
                and self.principals[owner]["kind"] == "service"
                and tier == "fast" and rules["fastAuto"]
                and request["mutation"] in ("create", "correct", "retract")):
            needs_review = False
        result.update({"requiresReview": needs_review, "reviewers": sorted(rules["reviewers"])})
        if operation == "review" and rules["separateReview"] and actor == trusted.get("proposedBy"):
            return deny("an independent reviewer is required")
        slow_review = tier == "slow" or request["mutation"] in ("supersede", "retract", "delete", "promote")
        if operation == "review" and slow_review and self.principals[actor]["kind"] != "human":
            return deny("slow-tier review requires a human authority")
        if operation == "commit" and needs_review:
            reviewer = trusted.get("approvedBy")
            if reviewer not in rules["reviewers"] or reviewer not in rules["readers"]:
                return deny("review approval is required")
            if rules["separateReview"] and reviewer == trusted.get("proposedBy", actor):
                return deny("an independent reviewer is required")
            if slow_review and self.principals[reviewer]["kind"] != "human":
                return deny("slow-tier review requires a human authority")
        result["allowed"] = True
        return result


def load_policy(root, config):
    """Load only operator-pinned policy, ontology and practice bytes, never a request's paths."""
    root = Path(root)

    def read(path, expected):
        relative = local_path(path)
        if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise PolicyError("policy sources cannot follow symlinks")
        raw = (root / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise PolicyError(f"pinned policy source changed: {path}")
        return raw

    policy = Policy(json.loads(read(config["path"], config["sha256"])),
                    json.loads(read("brain-schema.json", config["ontologySha256"])))
    for scope in policy.scopes.values():
        practice = scope["practice"]
        read(practice["path"], practice["sha256"])
    return policy
