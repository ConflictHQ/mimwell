"""Verify Astrolift brain read tokens where the brain serves them (#459).

Astrolift (astrolift-app `backend/astrolift_registry/brain_tokens.py` and
`brain_apps.py`) mints an ES256 JWT for one caller and one brain and hands it to
clients with the header to send it in, `X-Astrolift-Brain-Token`:

    header   alg ES256, kid
    claims   iss    the install's URL
             aud    the brain app's guid
             sub    the user's guid, or `app:<guid>` for an app hosted on the brain
             email  the user's email (users only)
             scope  brain:read
             iat, exp (15 minutes for users, a year for app tokens), jti

The install publishes its public keys at `<install URL>/api/brains/v1/jwks.json`;
an app token is revoked by unpublishing its key.

`TokenVerifier` checks that contract and nothing looser: the header must name
ES256 and a key id, and nothing else in it is trusted (no `jku`, `x5u` or embedded
`jwk`; a `crit` header refuses); the signature must verify against a key from the
configured JWKS URL; `iss` must equal the configured issuer and `aud` must be, or
contain, the configured audience; `exp`, `iat` and `nbf` hold with a 30 second
leeway; `scope` must include `brain:read`.

Keys come over HTTPS (plain HTTP only for a loopback host, for local runs), at most
64 KiB, without redirects. They are cached for five minutes (the JWKS's own
max-age); an unknown key id refetches at most once every 30 seconds, so made-up
key ids cannot hammer the install. When a refresh fails, the last good set keeps
answering for up to an hour; past that, or with no set yet, verification is
unavailable rather than open.

Errors never carry the token or its claims.

The optional contract-1 read-principal consumer is disabled unless the host
explicitly supplies `typed_principals_enabled=True` and its expected org GUID.
It accepts only signed canonical GUID claims for org/team/workload/app and
returns read principals separately from email. The configured org is exact;
the existing 8192-byte token ceiling bounds parsing locally. This consumer does
not change issuer behavior, native identity mappings, or writer grants.
"""
from __future__ import annotations

import base64
import dataclasses
import http.client
import ipaddress
import json
import re
from threading import Lock
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ALGORITHM = "ES256"
SCOPE = "brain:read"
JWKS_PATH = "/api/brains/v1/jwks.json"
MAX_TOKEN_BYTES = 8192
MAX_JWKS_BYTES = 64 * 1024
FETCH_TIMEOUT_SECONDS = 5
CACHE_SECONDS = 300
REFETCH_SECONDS = 30
MAX_STALE_SECONDS = 3600
LEEWAY_SECONDS = 30
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


class TokenError(Exception):
    """The token is missing, malformed, unsigned by a published key or out of contract."""


class KeysUnavailable(Exception):
    """The verifier holds no usable key set, so it cannot decide."""


@dataclasses.dataclass(frozen=True)
class Caller:
    """Who a verified token speaks for. `email` is empty for an app token."""

    subject: str
    email: str
    expires: int
    access_principals: tuple[str, ...] = ()
    contract: str | None = None


def _b64url(segment):
    if not _SEGMENT.fullmatch(segment):
        raise TokenError("malformed token")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError:
        raise TokenError("malformed token") from None


def _json_object(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def constant(_):
        raise ValueError("non-finite number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise TokenError("malformed token") from None
    if not isinstance(value, dict):
        raise TokenError("malformed token")
    return value


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_jwks_url(url):
    """The URL keys may come from: https, or plain http to a loopback host only."""
    parts = urlsplit(url or "")
    if parts.username or parts.password or not parts.hostname:
        raise ValueError("BRAIN_MCP_JWKS_URL must be an https URL with no credentials in it")
    if parts.scheme == "https" or (parts.scheme == "http" and _loopback(parts.hostname)):
        return url
    raise ValueError("BRAIN_MCP_JWKS_URL must be an https URL (plain http only for a loopback host)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_jwks(url):
    """GET the JWKS: no redirects, a timeout and a size ceiling."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "mimwell-brain-mcp"})
    try:
        response = opener.open(request, timeout=FETCH_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        exc.close()  # an error response still holds its connection
        raise ValueError(f"JWKS answered {exc.code}") from None
    with response:
        if response.status != 200:
            raise ValueError("unexpected JWKS status")
        body = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("JWKS exceeds its size limit")
    return body


def parse_jwks(raw):
    """kid -> public key for every usable P-256 signing key; a repeated kid is dropped."""
    from cryptography.hazmat.primitives.asymmetric import ec

    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS has no keys array")
    keys, repeated = {}, set()
    for jwk in document["keys"]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue
        if jwk.get("use", "sig") != "sig" or jwk.get("alg", ALGORITHM) != ALGORITHM:
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid or not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
            continue
        try:
            x, y = _b64url(jwk["x"]), _b64url(jwk["y"])
            if len(x) != 32 or len(y) != 32:
                continue
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                ec.SECP256R1()).public_key()
        except (TokenError, ValueError):
            continue
        if kid in keys:
            repeated.add(kid)
        keys[kid] = key
    for kid in repeated:
        del keys[kid]
    return keys


_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# The existing encoded-token ceiling bounds this local parser work. This is not
# an issuer guarantee or a cross-service claim-size contract.
MAX_TYPED_TEAM_ENTRIES = MAX_TOKEN_BYTES // 38


def _canonical_guid(value):
    return isinstance(value, str) and _GUID.fullmatch(value) is not None


class TokenVerifier:
    """Verify brain read tokens for one brain (`audience`) of one install (`issuer`)."""

    def __init__(self, *, jwks_url, issuer, audience, fetch=fetch_jwks, clock=time.time,
                 typed_principals_enabled=False, expected_org_guid=None):
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("BRAIN_MCP_ISSUER must name the install that issues brain tokens")
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError("BRAIN_MCP_AUDIENCE must name this brain (its Astrolift app id)")
        self.jwks_url = check_jwks_url(jwks_url)
        self.issuer = issuer
        self.audience = audience
        self._fetch = fetch
        self._clock = clock
        if not isinstance(typed_principals_enabled, bool):
            raise ValueError("typed principal opt-in must be boolean")
        if typed_principals_enabled and not _canonical_guid(expected_org_guid):
            raise ValueError("typed principals require a canonical expected organization GUID")
        if not typed_principals_enabled and expected_org_guid is not None:
            raise ValueError("expected organization GUID requires typed principal opt-in")
        self.typed_principals_enabled = typed_principals_enabled
        self.expected_org_guid = expected_org_guid
        self._lock = Lock()
        self._keys = None
        self._fetched_at = None
        self._attempted_at = None

    def _refresh(self, now):
        self._attempted_at = now
        try:
            keys = parse_jwks(self._fetch(self.jwks_url))
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            if self._keys is not None and now - self._fetched_at < MAX_STALE_SECONDS:
                return
            self._keys = None
            raise KeysUnavailable("brain token keys are unavailable") from None
        self._keys, self._fetched_at = keys, now

    def _key(self, kid):
        now = self._clock()
        with self._lock:
            retry = self._attempted_at is None or now - self._attempted_at >= REFETCH_SECONDS
            if (self._keys is None or now - self._fetched_at >= CACHE_SECONDS) and retry:
                self._refresh(now)
                retry = False
            if self._keys is None:
                raise KeysUnavailable("brain token keys are unavailable")
            key = self._keys.get(kid)
            if key is None and retry:
                self._refresh(now)
                key = self._keys.get(kid)
        if key is None:
            raise TokenError("token signed by an unknown key")
        return key

    def verify(self, token):
        """The caller a valid token speaks for, or TokenError / KeysUnavailable."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
            raise TokenError("missing or oversized token")
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("malformed token")
        header = _json_object(_b64url(parts[0]))
        if header.get("alg") != ALGORITHM or "crit" in header:
            raise TokenError("unsupported token algorithm")
        if str(header.get("typ", "JWT")).upper() != "JWT":
            raise TokenError("unsupported token type")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise TokenError("token names no key")
        claims = _json_object(_b64url(parts[1]))
        signature = _b64url(parts[2])
        if len(signature) != 64:
            raise TokenError("malformed signature")
        key = self._key(kid)
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        try:
            key.verify(encode_dss_signature(r, s), f"{parts[0]}.{parts[1]}".encode("ascii"),
                       ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise TokenError("bad token signature") from None
        return self._caller(claims)

    def _caller(self, claims):
        now = self._clock()
        if claims.get("iss") != self.issuer:
            raise TokenError("token from another issuer")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
        if self.audience not in [a for a in audiences if isinstance(a, str)]:
            raise TokenError("token for another brain")
        expires, issued, not_before = claims.get("exp"), claims.get("iat"), claims.get("nbf")
        if not _number(expires) or now >= expires + LEEWAY_SECONDS:
            raise TokenError("expired token")
        if not _number(issued) or issued > now + LEEWAY_SECONDS:
            raise TokenError("token issued in the future")
        if not_before is not None and (not _number(not_before) or not_before > now + LEEWAY_SECONDS):
            raise TokenError("token not yet valid")
        scope = claims.get("scope")
        if not isinstance(scope, str) or SCOPE not in scope.split():
            raise TokenError("token lacks the brain:read scope")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise TokenError("token names no subject")
        email = claims.get("email")
        return self._verified_caller(claims, subject, email, int(expires))

    def _verified_caller(self, claims, subject, email, expires):
        typed_claims = {"contract", "sub_kind", "org", "teams", "agent", "app"}
        explicit = typed_claims.intersection(claims)
        if not explicit:
            return Caller(subject=subject, email=email.strip() if isinstance(email, str) else "", expires=expires)
        if claims.get("contract") != "1":
            raise TokenError("unsupported explicit token contract")
        if not self.typed_principals_enabled:
            raise TokenError("typed token contract is not enabled for this brain")
        if explicit != {"contract", "sub_kind", "org", "teams"} | ({"agent"} if claims.get("sub_kind") == "agent" else set()) | ({"app"} if claims.get("sub_kind") == "app" else set()):
            raise TokenError("malformed typed token contract")
        if claims.get("sub_kind") not in ("user", "agent", "app"):
            raise TokenError("unknown typed token subject kind")
        if claims.get("org") != self.expected_org_guid or not _canonical_guid(claims.get("org")):
            raise TokenError("typed token organization does not match this brain")
        teams = claims.get("teams")
        if (not isinstance(teams, list) or len(teams) > MAX_TYPED_TEAM_ENTRIES
                or any(not _canonical_guid(team) for team in teams)
                or len(set(teams)) != len(teams)):
            raise TokenError("malformed typed token teams")
        kind = claims["sub_kind"]
        typed = [f"team:{team}" for team in teams]
        if kind == "user":
            if not isinstance(email, str) or not email.strip() or "agent" in claims or "app" in claims:
                raise TokenError("malformed typed user token")
        elif kind == "agent":
            if (not _canonical_guid(claims.get("agent")) or "app" in claims
                    or subject != f"agent:{claims.get('agent')}"):
                raise TokenError("malformed typed agent token")
            typed.append(f"agent:{claims['agent']}")
        else:
            if (not _canonical_guid(claims.get("app")) or "agent" in claims
                    or subject != f"app:{claims.get('app')}"):
                raise TokenError("malformed typed app token")
            typed.append(f"app:{claims['app']}")
        # Non-person principals are read-only here. Do not let an optional email
        # claim turn an app/workload token into a native proposal actor.
        trusted_email = email.strip() if kind == "user" and isinstance(email, str) else ""
        return Caller(subject=subject, email=trusted_email, expires=expires,
                      access_principals=tuple(typed), contract="1")
