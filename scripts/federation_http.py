"""Authenticated JSON transport for one explicitly registered federation realm.

Production clients require HTTPS. Plain HTTP is an explicit loopback-only option
for local conformance tests. Endpoints, credentials and source factories belong
to the host; JSON requests cannot provide them or impersonate a source principal.
"""
from copy import deepcopy
import datetime as dt
import hashlib
import hmac
import http.client
import ipaddress
import re
import secrets
import ssl
from urllib.parse import urlsplit

from brain_federation import FederationError, fields, strings, text
from context_bundle import encode
from context_host import decode, MAX_INPUT_BYTES
from evidence import validate_record
from federation_resolution import LocalRecordSource, unavailable
from knowledge_policy import fingerprint, local_path, timestamp
from ontology import Registry

UNAVAILABLE_REASONS = {"unavailable", "offline", "revision-changed", "unsupported-contract", "maxBytes"}


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise FederationError("Invalid remote provenance digest")


def validate_outcome(outcome, target, authority, ontology, *, edge=False, registry=None, protection=None,
                     allow_protection=False):
    if not isinstance(outcome, dict):
        raise FederationError("Invalid remote outcome")
    if outcome.get("status") == "unavailable":
        fields(outcome, ("status", "reason"))
        allowed = UNAVAILABLE_REASONS | ({'protection-changed', 'protection-unavailable'} if allow_protection else set())
        if outcome["reason"] not in allowed:
            raise FederationError("Unknown remote outcome")
        return
    fields(outcome, ("status", "record", "provenance"))
    if outcome["status"] != "resolved":
        raise FederationError("Unknown remote outcome")
    record, provenance = outcome["record"], outcome["provenance"]
    if not isinstance(record, dict) or (fingerprint(record) if edge else record.get("id")) != target["address"]:
        raise FederationError("Remote record address mismatch")
    provenance_fields = ("participant", "realm", "authority", "revision", "recordSha256", "policySha256", "ontologySha256",
                         "bindingsSha256", "publicationSha256", "evaluatedAt")
    if isinstance(provenance, dict) and "store" in provenance:
        provenance_fields += ("store",)
    if protection is not None:
        provenance_fields += ('protection',)
    fields(provenance, provenance_fields)
    if protection is not None:
        from federation_protection import record_receipt
        record_receipt(provenance['protection'], protection)
    if "store" in provenance:
        store = provenance["store"]
        fields(store, ("kind", "bindingSha256", "snapshotSha256", "state", "recordRevision"))
        if target["realm"] != "brain" or store["kind"] != "sqlite-authority" or store["state"] != "active":
            raise FederationError("Invalid structured authority provenance")
        for key in ("bindingSha256", "snapshotSha256"):
            digest(store[key])
        if not isinstance(store["recordRevision"], str) or not re.fullmatch(r"[1-9][0-9]*:[0-9a-f]{64}", store["recordRevision"]):
            raise FederationError("Invalid authority record revision")
    if any(provenance[k] != target[k] for k in ("participant", "realm", "revision")) or provenance["authority"] != authority:
        raise FederationError("Remote source identity or revision mismatch")
    for key in ("recordSha256", "policySha256", "ontologySha256", "bindingsSha256", "publicationSha256"):
        digest(provenance[key])
    if provenance["recordSha256"] != fingerprint(record):
        raise FederationError("Remote record digest mismatch")
    timestamp(provenance["evaluatedAt"])
    if target["realm"] == "brain":
        if provenance["ontologySha256"] != fingerprint(ontology):
            raise FederationError("Remote ontology revision mismatch")
        (registry or Registry(ontology)).validate_records([] if edge else [record], [record] if edge else [])
    elif target["realm"] == "code" and not edge:
        fields(record, ("id", "kind", "source", "text", "data"))
        if record["kind"] != "Code" or not isinstance(record["text"], str):
            raise FederationError("Invalid code record")
        text(record["source"])
        local_path(record["source"])
        data = record["data"]
        fields(data, ("sha256", "symbol", "startLine", "endLine"))
        digest(data["sha256"])
        if (type(data["startLine"]) is not int or type(data["endLine"]) is not int
                or data["startLine"] < 1 or data["endLine"] < data["startLine"] - 1):
            raise FederationError("Invalid code span")
        if data["symbol"] is not None:
            text(data["symbol"])
        elif hashlib.sha256(record["text"].encode()).hexdigest() != data["sha256"]:
            raise FederationError("Whole-file code digest mismatch")
    else:
        raise FederationError("Unsupported remote realm")
    validate_record(record)


def validate_search_outcome(outcome, target, authority, ontology, query, max_matches):
    """Validate source attribution and recompute ranking; remote scores are untrusted."""
    from context_bundle import _evidence_gaps
    from context_search import METHOD, score_record, terms
    if isinstance(outcome, dict) and outcome.get('status') == 'unavailable':
        validate_outcome(outcome, target, authority, ontology)
        return
    fields(outcome, ('status', 'method', 'matches', 'truncation'))
    if outcome['status'] != 'searched' or outcome['method'] != METHOD:
        raise FederationError('Unsupported remote search result')
    if not isinstance(outcome['matches'], list) or len(outcome['matches']) > max_matches:
        raise FederationError('Remote search exceeded match budget')
    strings(outcome['truncation'])
    if set(outcome['truncation']) - {'maxBytes', 'maxMatches'}:
        raise FederationError('Unknown remote search truncation')
    seen, keys = set(), []
    for match in outcome['matches']:
        fields(match, ('record', 'provenance', 'matchedTerms', 'score', 'gaps'))
        record = match['record']
        if not isinstance(record, dict):
            raise FederationError('Invalid search record')
        address = record.get('id')
        text(address)
        if address in seen:
            raise FederationError('Repeated remote search address')
        seen.add(address)
        validate_outcome({'status': 'resolved', 'record': record, 'provenance': match['provenance']},
                         {**target, 'address': address}, authority, ontology)
        matched, score = score_record(record, set(terms(query)))
        gaps = _evidence_gaps(record, address, timestamp(match['provenance']['evaluatedAt']))
        if (not matched or match['matchedTerms'] != matched or type(match['score']) is not int
                or match['score'] != score or match['gaps'] != gaps):
            raise FederationError('Remote search score or evidence gaps disagree with record')
        keys.append((-len(matched), -score, address))
    if keys != sorted(keys):
        raise FederationError('Remote search ordering is inconsistent')


class RemoteRecordSource:
    transport = "remote"

    def __init__(self, *, participant, realm, authority, endpoint, token, consumer,
                 ontology=None, timeout=5, max_response_bytes=1024 * 1024, ca_pem=None,
                 allow_loopback_http=False, max_request_bytes=65536):
        for value in (participant, realm, authority, endpoint, token, consumer):
            text(value)
        if any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise FederationError("Invalid bearer credential")
        parsed = urlsplit(endpoint)
        if (parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query
                or not parsed.hostname or not parsed.path.startswith("/")
                or any(ord(c) < 33 or ord(c) > 126 for c in endpoint)):
            raise FederationError("Invalid configured resolver endpoint")
        if parsed.scheme != "https":
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
            if parsed.scheme != "http" or not allow_loopback_http or not loopback:
                raise FederationError("Remote resolvers require HTTPS")
        if type(timeout) not in (float, int) or not 0 < timeout <= 60:
            raise FederationError("Invalid remote I/O timeout")
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_INPUT_BYTES:
            raise FederationError("Invalid remote response limit")
        if type(max_request_bytes) is not int or not 1 <= max_request_bytes <= MAX_INPUT_BYTES:
            raise FederationError('Invalid remote request limit')
        if realm == "brain":
            if not isinstance(ontology, dict):
                raise FederationError("A remote brain requires its configured ontology")
            Registry(ontology)
        elif realm != "code":
            raise FederationError("Unsupported remote realm")
        self.participant, self.realm, self.authority = participant, realm, authority
        self._endpoint, self._token, self._consumer = endpoint, token, consumer
        self._scheme, self._host, self._port, self._path = parsed.scheme, parsed.hostname, parsed.port, parsed.path
        self._ontology, self._timeout = deepcopy(ontology), timeout
        if ca_pem is not None:
            text(ca_pem)
            ssl.create_default_context(cadata=ca_pem)
        self._limit, self._ca_pem = max_response_bytes, ca_pem
        self._request_limit = max_request_bytes

    def binding(self):
        return fingerprint({"participant": self.participant, "realm": self.realm, "authority": self.authority,
                            "endpoint": self._endpoint, "credentialSha256": hashlib.sha256(self._token.encode()).hexdigest(),
                            "consumer": self._consumer, "ontology": self._ontology,
                            "timeout": self._timeout, "maxResponseBytes": self._limit, "caPem": self._ca_pem,
                            "maxRequestBytes": self._request_limit})

    def resolve(self, address, *, revision, audience, consumer, now, max_bytes=None):
        if consumer != self._consumer:
            return unavailable()
        if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
            raise FederationError("Invalid remote response budget")
        target = {"participant": self.participant, "realm": self.realm, "address": address, "revision": revision}
        limit = min(self._limit, max_bytes) if max_bytes is not None else self._limit
        nonce = secrets.token_hex(16)
        body = encode({"protocolVersion": "1.0", "target": target, "audience": audience, "nonce": nonce,
                       "budget": {"maxBytes": limit}})
        return self._exchange(body, target, nonce, limit, version='1.0',
                              validator=lambda outcome: validate_outcome(outcome, target, self.authority, self._ontology))

    def search(self, query, *, revision, audience, consumer, now, max_matches, max_bytes):
        from federation_search import positive, validate_query
        validate_query(query)
        positive(max_matches)
        positive(max_bytes)
        if consumer != self._consumer:
            return unavailable()
        target = {'participant': self.participant, 'realm': self.realm, 'revision': revision}
        nonce = secrets.token_hex(16)
        limit = min(self._limit, max_bytes)
        body = encode({'protocolVersion': '1.1', 'operation': 'search', 'target': target,
                       'audience': audience, 'nonce': nonce, 'query': query,
                       'budget': {'maxBytes': limit, 'maxMatches': max_matches}})
        return self._exchange(body, target, nonce, limit, version='1.1',
            validator=lambda outcome: validate_search_outcome(outcome, target, self.authority,
                                                               self._ontology, query, max_matches))

    def snapshot(self, *, revision, audience, consumer, now, max_nodes, max_edges, max_bytes,
                 protection_sha256=None):
        from federation_composition import budgets, validate_snapshot
        budget = {'maxNodes': max_nodes, 'maxEdges': max_edges, 'maxBytes': max_bytes}
        budgets(budget, source=True)
        if consumer != self._consumer:
            return unavailable()
        target = {'participant': self.participant, 'realm': self.realm, 'revision': revision}
        nonce = secrets.token_hex(16)
        limit = min(self._limit, max_bytes)
        version = '1.3' if protection_sha256 is not None else '1.2'
        extra = {}
        if protection_sha256 is not None:
            digest(protection_sha256)
            extra['protectionSha256'] = protection_sha256
        body = encode({'protocolVersion': version, 'operation': 'compose', 'target': target,
                       'audience': audience, 'nonce': nonce, 'budget': {**budget, 'maxBytes': limit}, **extra})
        return self._exchange(body, target, nonce, limit, version=version,
            validator=lambda outcome: validate_snapshot(outcome, target, self.authority,
                                                         self._ontology, budget, protection_sha256=protection_sha256))

    def revalidate_witnesses(self, witnesses, *, revision, audience, consumer, now, protection_sha256=None):
        from source_revalidation import validate_witnesses
        validate_witnesses(witnesses)
        if consumer != self._consumer:
            return False
        if protection_sha256 is not None:
            digest(protection_sha256)
        target = {'participant': self.participant, 'realm': self.realm, 'revision': revision, 'authority': self.authority}
        nonce = secrets.token_hex(16)
        expected = {'status': 'revalidated', 'witnessesSha256': fingerprint(witnesses)}

        def validate(outcome):
            if outcome != expected:
                raise FederationError('Source revalidation did not match the exact witnesses')

        body = encode({'protocolVersion': '1.4', 'operation': 'revalidate', 'target': target,
                       'audience': audience, 'nonce': nonce, 'budget': {'maxBytes': self._limit},
                       'witnesses': witnesses, 'protectionSha256': protection_sha256})
        outcome = self._exchange(body, target, nonce, self._limit, version='1.4', validator=validate)
        return outcome == expected

    def _exchange(self, body, target, nonce, limit, *, version, validator):
        if len(body) > self._request_limit:
            return unavailable('maxBytes')
        connection = None
        try:
            if self._scheme == "https":
                context = ssl.create_default_context(cadata=self._ca_pem)
                connection = http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout, context=context)
            else:
                connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
            connection.request("POST", self._path, body=body, headers={
                "Authorization": "Bearer " + self._token, "Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            if response.status in (401, 403, 404):
                return unavailable()
            if response.status == 413:
                return unavailable("maxBytes")
            if response.status in (429, 502, 503, 504):
                return unavailable("offline")
            # http.client never follows redirects or environment proxies.
            if (response.status != 200 or response.getheader("Content-Type", "").split(";")[0].strip() != "application/json"
                    or response.getheader("Content-Encoding", "identity") != "identity"):
                return unavailable("invalid-response")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > limit):
                return unavailable("maxBytes" if length.isdigit() else "invalid-response")
            raw = response.read(limit + 1)
            if len(raw) > limit:
                return unavailable("maxBytes")
            envelope = decode(raw)
            fields(envelope, ("protocolVersion", "target", "outcome", "nonce"))
            if envelope["protocolVersion"] != version or envelope["target"] != target or envelope["nonce"] != nonce:
                return unavailable("invalid-response")
            validator(envelope["outcome"])
            return deepcopy(envelope["outcome"])
        except (OSError, http.client.HTTPException):
            return unavailable("offline")
        except (ValueError, TypeError, KeyError):
            return unavailable("invalid-response")
        finally:
            if connection is not None:
                connection.close()


class ResolverEndpoint:
    """Transport-independent server handler; the hosting service supplies TLS.

    Credential records contain a SHA-256 of a bearer secret, its authenticated
    consumer and allowed federation audiences. ``factory(consumer, now)`` must
    build a fresh LocalRecordSource using source-owned policy/principal mappings.
    """

    def __init__(self, *, credentials, factory, clock=None, max_request_bytes=65536,
                 max_response_bytes=1024 * 1024, search_enabled=False, composition_enabled=False):
        if type(search_enabled) is not bool:
            raise FederationError('Source search must be explicitly enabled or disabled')
        self._search_enabled = search_enabled
        if type(composition_enabled) is not bool:
            raise FederationError('Source composition must be explicitly selected')
        self._composition_enabled = composition_enabled
        if not (isinstance(credentials, list) or callable(credentials)) or not callable(factory):
            raise FederationError("Invalid resolver endpoint configuration")
        if isinstance(credentials, list):
            self._validate_credentials(credentials)
        for limit in (max_request_bytes, max_response_bytes):
            if type(limit) is not int or not 1 <= limit <= MAX_INPUT_BYTES:
                raise FederationError("Invalid endpoint byte limits")
        self._credentials = credentials if callable(credentials) else deepcopy(credentials)
        self._factory = factory
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
        self._input_limit, self._output_limit = max_request_bytes, max_response_bytes

    @staticmethod
    def _validate_credentials(credentials):
        if not isinstance(credentials, list) or len(credentials) > 1024:
            raise FederationError('Invalid source credential provider')
        seen = set()
        for credential in credentials:
            optional = ('expiresAt',) if isinstance(credential, dict) and 'expiresAt' in credential else ()
            fields(credential, ("sha256", "consumer", "audiences") + optional)
            digest(credential["sha256"])
            text(credential["consumer"])
            strings(credential["audiences"])
            if credential.get('expiresAt') is not None:
                timestamp(credential['expiresAt'])
            if credential["sha256"] in seen:
                raise FederationError("Ambiguous resolver credential")
            seen.add(credential["sha256"])

    def _authenticate(self, authorization, now):
        if (not isinstance(authorization, str) or len(authorization) > 4103
                or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/\-]+=*', authorization, re.IGNORECASE)):
            return None
        supplied = hashlib.sha256(authorization[7:].encode('ascii')).hexdigest()
        records = self._credentials() if callable(self._credentials) else self._credentials
        self._validate_credentials(records)
        current = timestamp(now)
        credential = None
        for entry in records:
            if (hmac.compare_digest(supplied, entry['sha256'])
                    and (entry.get('expiresAt') is None or current < timestamp(entry['expiresAt']))):
                credential = deepcopy(entry)
        return credential

    def handle(self, raw, authorization):
        """Return (HTTP status, UTF-8 JSON bytes); never echo errors or credentials."""
        def failure(status):
            return status, b""

        if not isinstance(raw, bytes) or len(raw) > self._input_limit:
            return failure(413)
        try:
            now = self._clock()
            timestamp(now)
            credential = self._authenticate(authorization, now)
            if credential is None:
                return failure(401)
            request = decode(raw)
            searching = isinstance(request, dict) and request.get('protocolVersion') == '1.1'
            protected = isinstance(request, dict) and request.get('protocolVersion') == '1.3'
            composing = isinstance(request, dict) and request.get('protocolVersion') in ('1.2', '1.3')
            revalidating = isinstance(request, dict) and request.get('protocolVersion') == '1.4'
            if revalidating:
                from source_revalidation import validate_witnesses
                fields(request, ('protocolVersion', 'operation', 'target', 'audience', 'budget', 'nonce',
                                 'witnesses', 'protectionSha256'))
                fields(request['target'], ('participant', 'realm', 'revision', 'authority'))
                fields(request['budget'], ('maxBytes',))
                if request['operation'] != 'revalidate':
                    return failure(400)
                validate_witnesses(request['witnesses'])
                if request['protectionSha256'] is not None:
                    digest(request['protectionSha256'])
            elif composing:
                from federation_composition import budgets
                fields(request, ('protocolVersion', 'operation', 'target', 'audience', 'budget', 'nonce') +
                       (('protectionSha256',) if protected else ()))
                if protected:
                    digest(request['protectionSha256'])
                if request['operation'] != 'compose':
                    return failure(400)
                fields(request['target'], ('participant', 'realm', 'revision'))
                budgets(request['budget'], source=True)
            elif searching:
                from federation_search import positive, validate_query
                fields(request, ('protocolVersion', 'operation', 'target', 'audience', 'budget', 'nonce', 'query'))
                if request['operation'] != 'search':
                    return failure(400)
                fields(request['target'], ('participant', 'realm', 'revision'))
                fields(request['budget'], ('maxBytes', 'maxMatches'))
                validate_query(request['query'])
                positive(request['budget']['maxMatches'])
            else:
                fields(request, ('protocolVersion', 'target', 'audience', 'budget', 'nonce'))
                fields(request['target'], ('participant', 'realm', 'address', 'revision'))
                fields(request['budget'], ('maxBytes',))
            for value in request["target"].values():
                text(value)
            text(request["audience"])
            if not isinstance(request["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"]):
                return failure(400)
            limit = request["budget"]["maxBytes"]
            if type(limit) is not int or limit < 1:
                return failure(400)
            if revalidating and limit > MAX_INPUT_BYTES:
                return failure(400)
            if request["protocolVersion"] not in ('1.0', '1.1', '1.2', '1.3', '1.4'):
                return failure(400)
            if request["audience"] not in credential["audiences"]:
                return failure(403)
            if (searching and not self._search_enabled) or (composing and not self._composition_enabled):
                result = encode({'protocolVersion': request['protocolVersion'], 'target': request['target'],
                                 'outcome': unavailable('unsupported-contract'), 'nonce': request['nonce']})
                return (200, result) if len(result) <= min(limit, self._output_limit) else failure(413)
            now = self._clock()
            timestamp(now)
            if self._authenticate(authorization, now) != credential:
                return failure(401)
            source = self._factory(credential["consumer"], now)
            if not isinstance(source, LocalRecordSource):
                return failure(503)
            source_binding = source.binding()
            target = request["target"]
            if (source.participant, source.realm) != (target["participant"], target["realm"]):
                outcome = unavailable()
            elif revalidating:
                if (source.authority != target['authority']
                        or (not self._composition_enabled and any(w['kind'] == 'edge' for w in request['witnesses']))):
                    outcome = unavailable()
                else:
                    valid = source.revalidate_witnesses(request['witnesses'], revision=target['revision'],
                        audience=request['audience'], consumer=credential['consumer'], now=self._clock(),
                        protection_sha256=request['protectionSha256']) is True
                    outcome = ({'status': 'revalidated', 'witnessesSha256': fingerprint(request['witnesses'])}
                               if valid else unavailable())
            elif composing:
                overhead = len(encode({'protocolVersion': request['protocolVersion'], 'target': target,
                                       'outcome': {}, 'nonce': request['nonce']})) - len(encode({}))
                available_bytes = min(limit, self._output_limit) - overhead
                if available_bytes < 1:
                    return failure(413)
                if not callable(getattr(source, 'snapshot', None)):
                    outcome = unavailable('unsupported-contract')
                else:
                    outcome = source.snapshot(revision=target['revision'], audience=request['audience'],
                                              consumer=credential['consumer'], now=now,
                                              max_nodes=request['budget']['maxNodes'],
                                              max_edges=request['budget']['maxEdges'], max_bytes=available_bytes,
                                              **({'protection_sha256': request['protectionSha256']} if protected else {}))
            elif searching:
                overhead = len(encode({'protocolVersion': '1.1', 'target': target,
                                       'outcome': {}, 'nonce': request['nonce']})) - len(encode({}))
                available_bytes = min(limit, self._output_limit) - overhead
                if available_bytes < 1:
                    return failure(413)
                outcome = source.search(request['query'], revision=target['revision'], audience=request['audience'],
                                        consumer=credential['consumer'], now=now,
                                        max_matches=request['budget']['maxMatches'], max_bytes=available_bytes)
            else:
                outcome = source.resolve(target["address"], revision=target["revision"], audience=request["audience"],
                                         consumer=credential["consumer"], now=now)
            release_now = self._clock()
            timestamp(release_now)
            if self._authenticate(authorization, release_now) != credential:
                return failure(401)
            if outcome.get('status') != 'unavailable':
                current = self._factory(credential['consumer'], release_now)
                valid = isinstance(current, LocalRecordSource) and current.binding() == source_binding
                if valid and revalidating:
                    valid = current.revalidate_witnesses(request['witnesses'], revision=target['revision'],
                        audience=request['audience'], consumer=credential['consumer'], now=self._clock(),
                        protection_sha256=request['protectionSha256']) is True
                elif valid:
                    valid = current.revalidate(outcome, audience=request['audience'],
                                               consumer=credential['consumer'], now=self._clock())
                if not valid:
                    outcome = unavailable()
            if self._authenticate(authorization, self._clock()) != credential:
                return failure(401)
            result = encode({"protocolVersion": request['protocolVersion'], "target": target,
                             "outcome": outcome, "nonce": request["nonce"]})
            if len(result) > min(limit, self._output_limit):
                return failure(413)
            return 200, result
        except (ValueError, TypeError, KeyError, OSError):
            return failure(400)
        except Exception:
            return failure(503)
