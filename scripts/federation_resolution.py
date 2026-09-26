"""Bounded, revision-pinned local realm resolution with source-side release checks.

Source objects and publication approvals are authenticated host configuration.
No request selects a filesystem path, endpoint, principal or policy resource.
The optional HTTP transport uses the same source-side release boundary.
"""
from __future__ import annotations

import ast
from copy import copy, deepcopy
import hashlib
from pathlib import Path

from brain_federation import FederationError, fields, text
from context_access import ReadBoundary, record_paths
from context_bundle import encode
from context_host import MAX_INPUT_BYTES
from knowledge_policy import PolicyError, fingerprint, local_path, timestamp


class ResolutionBudgetError(FederationError):
    pass


def publication_key(participant, realm, authority, revision, record):
    return fingerprint({"participant": participant, "realm": realm, "authority": authority,
                        "revision": revision, "record": record})


def unavailable(reason="unavailable"):
    return {"status": "unavailable", "reason": reason}


def resolution_targets(request):
    fields(request, ('protocolVersion', 'targets', 'budget'))
    if request['protocolVersion'] != '1.0' or not isinstance(request['targets'], list):
        raise FederationError('Unsupported resolution request')
    fields(request['budget'], ('maxTargets', 'maxBytes'))
    for limit in request['budget'].values():
        if type(limit) is not int or limit < 1:
            raise FederationError('Resolution budgets must be positive integers')
    targets = {}
    for target in request['targets']:
        fields(target, ('participant', 'realm', 'address', 'revision'))
        for value in target.values():
            text(value)
        targets[fingerprint(target)] = deepcopy(target)
    return sorted(targets.values(), key=lambda t: (t['participant'], t['realm'], t['address'], t['revision']))


class LocalRecordSource:
    """A source-host read snapshot, independently authenticated for one consumer.

    ``records`` must be validated by the owning realm before construction (brain
    graphs through their ontology registry; code through ``load_code_records``).
    ``SQLiteRecordSource`` obtains structured records through a consistent read.
    Other journal/structured adapters must establish their own read/export point.
    The revision binds exact snapshot records, not a claim of live-store freshness.
    """

    transport = "local"

    def __init__(self, *, participant, realm, authority, records, boundary,
                 consumer, publications, protection=None):
        for value in (participant, realm, authority, consumer):
            text(value)
        if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
            raise FederationError("Invalid realm records")
        by_id = {}
        for record in records:
            text(record.get("id"))
            text(record.get("kind"))
            if record["id"] in by_id:
                raise FederationError("Duplicate realm address")
            by_id[record["id"]] = deepcopy(record)
        if not isinstance(publications, dict):
            raise FederationError("Invalid source publication configuration")
        for key, release in publications.items():
            text(key)
            fields(release, ("audience", "resource", "approvedBy", "expiresAt"))
            for value in release.values():
                text(value)
            timestamp(release["expiresAt"])
        self._identity = (participant, realm, authority)
        self._revision = fingerprint(by_id)
        self._records = by_id
        self._boundary = deepcopy(boundary)
        self._consumer = consumer
        self._publications = deepcopy(publications)
        from federation_protection import SourceProtection
        self._protection = (None if protection is None else
                            SourceProtection(protection, resources=boundary.policy.resources))

    @property
    def participant(self):
        return self._identity[0]

    @property
    def realm(self):
        return self._identity[1]

    @property
    def authority(self):
        return self._identity[2]

    @property
    def revision(self):
        return self._revision

    def binding(self):
        """Pin source configuration; current authorization time is a result receipt.

        Excluding evaluation time lets a freshly authorized request use a basis
        discovered earlier without freezing grants or release expiry checks.
        """
        return fingerprint({"identity": self._identity, "revision": self.revision,
                            "policy": self._boundary.policy.binding,
                            "bindings": self._boundary.bindings, "publications": self._publications,
                            "consumer": self._consumer, "principal": self._boundary.actor,
                            "scopes": sorted(self._boundary.scopes),
                            "protection": None if self._protection is None else self._protection.sha256})

    def search(self, query, *, revision, audience, consumer, now, max_matches, max_bytes):
        from federation_search import source_search
        if self._protection is not None:
            return unavailable('unsupported-contract')
        return source_search(self, query, revision=revision, audience=audience,
                             consumer=consumer, now=now, max_matches=max_matches, max_bytes=max_bytes)

    def resolve(self, address, *, revision, audience, consumer, now, protected=False):
        return self._release(self._records.get(address), "nodes", address, revision=revision,
                             audience=audience, consumer=consumer, now=now, protected=protected)

    def revalidate(self, outcome, *, audience, consumer, now):
        """Recheck released rows against this fresh source without reranking.

        The caller must independently compare the original and current binding.
        This checks time-sensitive grants/publications as well as exact receipts;
        it does not lock an independent authority or recall delivered bytes.
        """
        status = outcome.get('status')
        if status == 'unavailable':
            return True
        if status == 'resolved':
            nodes, edges = [outcome], []
        elif status == 'searched':
            nodes, edges = outcome['matches'], []
        elif status == 'composed':
            nodes, edges = outcome['nodes'], outcome['edges']
        else:
            return False
        # The fresh factory may itself take time. Rebuild only the read boundary
        # at the release clock, retaining the already-pinned immutable records.
        current = copy(self)
        boundary = self._boundary
        current._boundary = ReadBoundary(boundary.policy, actor=boundary.actor, now=now,
                                        scopes=boundary.scopes, bindings=boundary.bindings)
        options = {'revision': self.revision, 'audience': audience, 'consumer': consumer,
                   'now': now, 'protected': self._protection is not None}

        def same(row, fresh):
            return (fresh['status'] == 'resolved' and row['record'] == fresh['record']
                    and {k: v for k, v in row['provenance'].items() if k != 'evaluatedAt'}
                    == {k: v for k, v in fresh['provenance'].items() if k != 'evaluatedAt'})

        for row in nodes:
            if not same(row, current.resolve(row['record']['id'], **options)):
                return False
        for row in edges:
            if not same(row, current._revalidate_edge(row, options)):
                return False
        return True

    def _revalidate_edge(self, row, options):
        return unavailable()

    def revalidate_witnesses(self, witnesses, *, revision, audience, consumer, now, protection_sha256=None):
        """Fresh native authorization of bounded fingerprints, never a new grant."""
        from source_revalidation import row_digest, validate_witnesses
        validate_witnesses(witnesses)
        if (consumer != self._consumer or revision != self.revision
                or protection_sha256 != (self._protection.sha256 if self._protection else None)):
            return False
        current = copy(self)
        boundary = self._boundary
        current._boundary = ReadBoundary(boundary.policy, actor=boundary.actor, now=now,
                                        scopes=boundary.scopes, bindings=boundary.bindings)
        options = {'revision': revision, 'audience': audience, 'consumer': consumer, 'now': now,
                   'protected': self._protection is not None}
        for witness in witnesses:
            if witness['kind'] == 'node':
                fresh = current.resolve(witness['address'], **options)
            else:
                edge = getattr(current, '_edges', {}).get(witness['address'])
                if edge is None:
                    return False
                fresh = current._revalidate_edge({'coordinate': {'address': witness['address']}, 'record': edge}, options)
            if fresh['status'] != 'resolved' or row_digest(fresh) != witness['sha256']:
                return False
        return True

    def _release(self, record, table, address, *, revision, audience, consumer, now,
                 key=None, extra_resources=(), protected=False):
        # The source host maps the consuming identity to its own principal.
        # Request JSON is never used to construct that mapping or boundary.
        boundary = self._boundary
        if protected != (self._protection is not None):
            return unavailable('unsupported-contract')
        if consumer != self._consumer or now != boundary.now:
            return unavailable()
        if record is None or not boundary.permits_record(table, address, record):
            return unavailable()
        key = publication_key(self.participant, self.realm, self.authority, self.revision, record) if key is None else key
        release = self._publications.get(key)
        if (release is None or release["audience"] != audience
                or timestamp(now) >= timestamp(release["expiresAt"])
                or not boundary.permits_resource(release["resource"], address)):
            return unavailable()
        if release["resource"] != boundary.bindings[table].get(address):
            return unavailable()
        reviewer = release["approvedBy"]
        if boundary.policy.principals.get(reviewer, {}).get("kind") != "human":
            return unavailable()
        # Release approval must also cover included evidence and its sources,
        # not just a more permissive resource attached to the outer record.
        resources = {release["resource"], *extra_resources}
        resources.update(boundary.bindings["paths"].get(path) for path in record_paths(record, edge=table == "edges"))
        evidence = record.get("evidence") or {}
        assertions = set(evidence.get("unresolvedAssertions", []))
        for assertion in evidence.get("assertions", []):
            assertions.add(assertion["id"])
            for relation in ("contradicts", "supersedes", "retracts"):
                assertions.update(assertion.get(relation, []))
        resources.update(boundary.bindings["assertions"].get(a) for a in assertions)
        for resource_id in resources:
            resource = boundary.policy.resources.get(resource_id)
            if resource is None:
                return unavailable()
            try:
                rules, _, _ = boundary.policy.effective(resource["scope"], timestamp(now))
            except PolicyError:
                return unavailable()
            if reviewer not in rules["reviewers"] or reviewer not in rules["readers"]:
                return unavailable()
        if revision != self.revision:
            return unavailable("revision-changed")
        result = {"status": "resolved", "record": deepcopy(record), "provenance": {
            "participant": self.participant, "realm": self.realm, "authority": self.authority,
            "revision": self.revision, "recordSha256": fingerprint(record),
            "policySha256": boundary.policy.binding["sha256"],
            "ontologySha256": boundary.policy.binding["ontologySha256"],
            "bindingsSha256": fingerprint(boundary.bindings),
            "publicationSha256": fingerprint({"key": key, "release": release}),
            "evaluatedAt": now}}
        if protected:
            result['provenance']['protection'] = {
                'policySha256': self._protection.sha256,
                'requirements': self._protection.for_resources(resources)}
        return result


def load_code_records(root, descriptors):
    """Load operator-pinned files or Python symbols; request addresses are opaque.

    Retains original path, whole-file digest and exact selected line span. Symbol
    lookup uses Python's AST, not text matching. Other languages support whole
    files here; their symbol resolvers are a separate capability.
    """
    root = Path(root)
    if root.is_symlink():
        raise FederationError("Code source root cannot be a symlink")
    if not isinstance(descriptors, dict):
        raise FederationError("Invalid code source descriptors")
    result = []
    for address, descriptor in sorted(descriptors.items()):
        text(address)
        fields(descriptor, ("path", "sha256", "symbol"))
        text(descriptor["sha256"])
        text(descriptor["path"])
        relative = local_path(descriptor["path"])
        if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise FederationError("Code sources cannot follow symlinks")
        with (root / relative).open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
            raise FederationError("Pinned code source changed or exceeds its limit")
        try:
            source = raw.decode("utf-8")
        except UnicodeError as exc:
            raise FederationError("Code source is not UTF-8 text") from exc
        lines = source.splitlines(keepends=True)
        start, end = 1, len(lines)
        symbol = descriptor["symbol"]
        if symbol is not None:
            text(symbol)
            if relative.suffix != ".py":
                raise FederationError("This resolver supports Python symbols and whole files")
            try:
                body = ast.parse(source).body
            except SyntaxError as exc:
                raise FederationError("Invalid Python source") from exc
            for segment in symbol.split("."):
                matches = [node for node in body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                           and node.name == segment]
                if len(matches) != 1:
                    raise FederationError("Code symbol is absent or ambiguous")
                node = matches[0]
                body = node.body
            start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
            end = node.end_lineno
        result.append({"id": address, "kind": "Code", "source": str(relative),
                       "text": "".join(lines[start - 1:end]),
                       "data": {"sha256": descriptor["sha256"], "symbol": symbol,
                                "startLine": start, "endLine": end}})
    return result


class FederationResolver:
    """Resolve explicit addresses using only operator-registered sources."""

    def __init__(self, view, *, sources, protection=None, served=None, access_log=None):
        from federation_http import RemoteRecordSource
        self._view = view
        if not isinstance(sources, dict) or any(not isinstance(s, (LocalRecordSource, RemoteRecordSource)) for s in sources.values()):
            raise FederationError("Invalid resolver registry")
        self._sources = dict(sources)
        self._source_filter = None
        from federation_protection import mount
        self._protection = {key: mount(value) for key, value in (protection or {}).items()}
        # Served sources are read only inside this host: search releases their
        # addresses, never record bodies, and logs every read (federated_search
        # refuses the response when access_log is missing or fails).
        self._served = {key: mount(value) for key, value in (served or {}).items()}
        if set(self._served) & set(self._protection) or (access_log is not None and not callable(access_log)):
            raise FederationError("Invalid served source registration")
        self._access_log = access_log

    @property
    def federation(self):
        return self._view.id

    @property
    def authorization(self):
        return self._view.authorization

    def restrict_sources(self, admit):
        """Host-only narrowing before reads and final checks; never a source grant."""
        if not callable(admit):
            raise FederationError('Source restriction requires a trusted host callback')
        narrowed, previous = copy(self), self._source_filter
        narrowed._source_filter = lambda target: ((previous is None or previous(deepcopy(target)) is True)
                                                  and admit(deepcopy(target)) is True)
        return narrowed

    def target_basis(self, target):
        """Host-only snapshot pin; never exposes handles or source policy bodies."""
        realm = self._view.realm(target["participant"], target["realm"])
        if realm is None:
            return None
        source = self._sources.get(realm["handle"])
        return fingerprint({"federation": self._view.id, "realm": realm,
                            "source": source.binding() if source is not None else None,
                            "protection": self._protection.get((target['participant'], target['realm']))
                                          or self._served.get((target['participant'], target['realm']))})

    def _collect(self, targets, read, *, max_bytes):
        """Stage bounded independent reads; reauthorize before combining them.

        This final sweep observes changes during earlier reads. It is not a lease
        over independently changing authorities; coordinated withdrawal is separate.
        """
        from source_revalidation import witnesses
        staged, used, limited = [], 0, False
        maximum = min(max_bytes, MAX_INPUT_BYTES)
        for target in targets:
            admitted = self._source_filter is None or self._source_filter(deepcopy(target)) is True
            basis = self.target_basis(target) if admitted else None
            minimum = len(encode([target, unavailable('maxBytes'), basis]))
            if used + minimum > maximum:
                limited = True
                break
            outcome = read(target) if admitted else unavailable()
            cost = len(encode([target, outcome, basis]))
            if used + cost > maximum:
                outcome, cost, limited = unavailable('maxBytes'), minimum, True
            staged.append((target, outcome, basis))
            used += cost
        # No global scoring or graph joins occur until every selected read above
        # has finished and its retained candidates pass native reauthorization.
        checked = []
        for target, outcome, basis in staged:
            if outcome['status'] != 'unavailable':
                try:
                    realm = self._view.realm(target['participant'], target['realm'])
                    source = self._sources.get(realm['handle']) if realm else None
                    selected = self._protection.get((target['participant'], target['realm']))
                    valid = ((self._source_filter is None or self._source_filter(deepcopy(target)) is True)
                             and source is not None and self.target_basis(target) == basis
                             and source.revalidate_witnesses(witnesses(outcome), revision=target['revision'],
                                 audience=self.federation, consumer=self.authorization['principal'],
                                 now=self.authorization['evaluatedAt'],
                                 protection_sha256=selected['policySha256'] if selected else None) is True)
                except (ValueError, TypeError, KeyError, OSError):
                    valid = False
                if not valid:
                    outcome = unavailable()
            checked.append((target, outcome))
        return checked, limited

    def compose(self, request):
        from federation_composition import compose
        return compose(self, request)

    def compose_source(self, target, *, max_nodes, max_edges, max_bytes, protected=False):
        realm = self._view.realm(target['participant'], target['realm'])
        if realm is None:
            return unavailable()
        if (target['participant'], target['realm']) in self._served:
            return unavailable('unsupported-contract')  # A composed graph would carry bodies out.
        if (realm['resolverVersion'] != '1.0' or realm['addressContract'] != '1.0'
                or not {'resolve', 'compose'}.issubset(realm['capabilities'])):
            return unavailable('unsupported-contract')
        if realm['transport'] == 'offline':
            return unavailable('offline')
        if target['revision'] != realm['revision']:
            return unavailable('revision-changed')
        source = self._sources.get(realm['handle'])
        if source is None:
            return unavailable('offline')
        if source.transport != realm['transport']:
            return unavailable('unsupported-transport')
        if (source.participant, source.realm, source.authority) != (
                target['participant'], target['realm'], realm['authority']):
            return unavailable()
        if not callable(getattr(source, 'snapshot', None)):
            return unavailable('unsupported-contract')
        selected = self._protection.get((target['participant'], target['realm']))
        if protected and selected is None:
            return unavailable('unsupported-contract')
        if not protected and selected is not None:
            return unavailable('unsupported-contract')
        authorization = self.authorization
        return source.snapshot(revision=target['revision'], audience=self._view.id,
                               consumer=authorization['principal'], now=authorization['evaluatedAt'],
                               max_nodes=max_nodes, max_edges=max_edges, max_bytes=max_bytes,
                               **({'protection_sha256': selected['policySha256']} if protected else {}))

    def search(self, request):
        from federation_search import federated_search
        return federated_search(self, request)

    def search_source(self, target, query, *, max_matches, max_bytes):
        """Host route checks precede source reads and remote requests."""
        realm = self._view.realm(target['participant'], target['realm'])
        if realm is None:
            return unavailable()
        if (target['participant'], target['realm']) in self._protection:
            return unavailable('unsupported-contract')
        if (realm['resolverVersion'] != '1.0' or realm['addressContract'] != '1.0'
                or not {'resolve', 'search'}.issubset(realm['capabilities'])):
            return unavailable('unsupported-contract')
        if realm['transport'] == 'offline':
            return unavailable('offline')
        if target['revision'] != realm['revision']:
            return unavailable('revision-changed')
        source = self._sources.get(realm['handle'])
        if source is None:
            return unavailable('offline')
        if source.transport != realm['transport']:
            return unavailable('unsupported-transport')
        if (source.participant, source.realm, source.authority) != (
                target['participant'], target['realm'], realm['authority']):
            return unavailable()
        authorization = self.authorization
        return source.search(query, revision=target['revision'], audience=self._view.id,
                             consumer=authorization['principal'], now=authorization['evaluatedAt'],
                             max_matches=max_matches, max_bytes=max_bytes)

    def resolve(self, request):
        request = deepcopy(request)
        ordered = resolution_targets(request)
        budget = request["budget"]
        result = {"protocolVersion": "1.0", "federation": self._view.id,
                  "authorization": self._view.authorization, "results": [], "truncation": []}

        def fits(candidate):
            return len(encode({**candidate, "truncation": ["maxBytes", "maxTargets"]})) <= budget["maxBytes"]

        if not fits(result):
            raise ResolutionBudgetError("Resolution budget cannot hold its envelope")
        if len(ordered) > budget["maxTargets"]:
            result["truncation"].append("maxTargets")
        collected, limited = self._collect(ordered[:budget['maxTargets']],
            lambda target: self._resolve(target, max_bytes=budget['maxBytes']), max_bytes=budget['maxBytes'])
        if limited:
            result['truncation'].append('maxBytes')
        for target, outcome in collected:
            candidate = deepcopy(result)
            candidate["results"].append({"target": target, **outcome})
            if fits(candidate):
                result = candidate
            elif "maxBytes" not in result["truncation"]:
                result["truncation"].append("maxBytes")
        result["truncation"].sort()
        return result

    def _resolve(self, target, *, max_bytes):
        realm = self._view.realm(target["participant"], target["realm"])
        if realm is None:
            return unavailable()
        if (target['participant'], target['realm']) in {**self._protection, **self._served}:
            return unavailable('unsupported-contract')
        if (realm["resolverVersion"] != "1.0" or realm["addressContract"] != "1.0"
                or "resolve" not in realm["capabilities"]):
            return unavailable("unsupported-contract")
        if realm["transport"] == "offline":
            return unavailable("offline")
        if target["revision"] != realm["revision"]:
            return unavailable("revision-changed")
        source = self._sources.get(realm["handle"])
        if source is None:
            return unavailable("offline")
        if source.transport != realm["transport"]:
            return unavailable("unsupported-transport")
        if (source.participant, source.realm, source.authority) != (
                target["participant"], target["realm"], realm["authority"]):
            return unavailable()
        authorization = self._view.authorization
        options = {"max_bytes": max_bytes} if source.transport == "remote" else {}
        return source.resolve(target["address"], revision=target["revision"], audience=self._view.id,
                              consumer=authorization["principal"], now=authorization["evaluatedAt"], **options)
