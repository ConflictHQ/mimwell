"""One principal per person at the host boundary (#212).

The principal a host trusts is an OIDC issuer + subject, written
``oidc:<issuer>#<subject>`` (an OIDC issuer carries no fragment, so ``#`` is
unambiguous). The person register (app/people.json) binds each entry to one
principal and lists the identities a host actually sees:

    person:<slug>          the register id (the compiled Person node)
    access:<email>         a Cloudflare Access authenticated email
    consumer:<actor>       a federation or context-service consumer credential actor
    oidc:<issuer>#<sub>    any provider's issuer + subject (Cognito, IAP, Entra ID)

``Principals.resolve`` maps any of them to the principal, or to None. A register
that binds one identity to two principals, or an identity to an entry with no
principal, is refused whole: a host must never guess who someone is.
access.js carries the JavaScript twin of these rules for the Worker.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from record_sources import record_slug

SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "people.schema.json"


class PrincipalError(ValueError):
    pass


def principal_id(issuer: str, subject: str) -> str:
    return f"oidc:{issuer}#{subject}"


def person_id(name: str) -> str:
    return "person:" + record_slug(name)


class Principals:
    def __init__(self, register):
        errors = list(Draft7Validator(json.loads(SCHEMA.read_text())).iter_errors(register))
        if errors:
            raise PrincipalError("Person register does not conform to people.schema.json")
        self._by_identity: dict[str, str] = {}
        for entry in register.get("people", []):
            principal = entry.get("principal")
            identities = entry.get("identities", {})
            bound = {person_id(entry["name"])}
            bound.update("access:" + email.strip().lower() for email in identities.get("access", []))
            bound.update("consumer:" + actor for actor in identities.get("consumers", []))
            bound.update(principal_id(o["issuer"], o["subject"]) for o in identities.get("oidc", []))
            if principal is None:
                if len(bound) > 1:
                    raise PrincipalError(f"{person_id(entry['name'])} lists identities but binds no principal")
                continue
            canonical = principal_id(principal["issuer"], principal["subject"])
            for identity in bound | {canonical}:
                if self._by_identity.setdefault(identity, canonical) != canonical:
                    raise PrincipalError(f"{identity} resolves to two principals")

    def resolve(self, identity: str) -> str | None:
        if not isinstance(identity, str):
            return None
        if identity.startswith("access:"):
            identity = identity.strip().lower()
        return self._by_identity.get(identity)

