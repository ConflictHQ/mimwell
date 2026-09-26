"""App grants over the native authority; no app can review or approve (#370)."""
from copy import deepcopy
import json
import re

from context_access import ReadBoundary
from context_bundle import ContextSnapshot, encode
from knowledge_policy import PolicyError, fingerprint, timestamp
from knowledge_store import StoreError


class AppDenied(PolicyError):
    pass


class AppConflict(StoreError):
    pass


def validate_grant(grant, contract, now):
    if not isinstance(grant, dict) or set(grant) != {'principal', 'read', 'owned', 'elsewhere'}:
        raise AppDenied('Missing app grant')
    principal = contract.policy.principals.get(grant['principal'])
    if not principal or principal['kind'] != 'service' or grant['elsewhere'] != 'propose':
        raise AppDenied('App must be a service with propose-only shared access')
    if not isinstance(grant['read'], list) or not grant['read'] or len(set(grant['read'])) != len(grant['read']):
        raise AppDenied('Explicit readable collections required')
    if any(key not in contract.collections for key in grant['read']):
        raise AppDenied('Unknown readable collection')
    if not isinstance(grant['owned'], dict) or not set(grant['owned']).issubset(grant['read']):
        raise AppDenied('Owned collections require read access')
    for key, retention in grant['owned'].items():
        if not isinstance(retention, dict) or set(retention) != {'retentionDays', 'onRemoval'}:
            raise AppDenied('Owned collections require retention')
        resource = contract.policy.resources[contract.collections[key]['resource']]
        rules, _, _ = contract.policy.effective(resource['scope'], timestamp(now))
        if contract.policy.scopes[resource['scope']]['owner'] != grant['principal'] or not rules['fastAuto'] or contract.policy.kinds[resource['kind']] != 'fast':
            raise AppDenied('Owned collection requires a service-owned fast scope')
        if (type(retention['retentionDays']) is not int or retention['retentionDays'] != rules['retentionDays']
                or retention['onRemoval'] not in ('retain', 'delete-after-retention')):
            raise AppDenied('Collection retention differs from policy')
    return grant


class AppBackend:
    def __init__(self, store, *, actor, app, grant, now, bindings, recipe):
        self.store, self.actor, self.app, self.now = store, actor, app, now
        self.grant = validate_grant(grant, store.contract, now)
        self.principal = grant['principal']
        if actor not in store.contract.policy.principals or actor == self.principal:
            raise AppDenied('A running user is required')
        allowed_resources = {store.contract.collections[key]['resource'] for key in grant['read']}
        self.bindings = {table: {identity: resource for identity, resource in entries.items() if resource in allowed_resources}
                         for table, entries in bindings.items()}
        self.recipe = recipe
        store.contract.app_owned = {store.contract.collections[key]['resource']: self.principal for key in grant['owned']}

    def _readable(self, collection):
        return (collection in self.grant['read'] and all(
            self.store.contract.can_read(collection, actor, self.now) for actor in (self.actor, self.principal)))

    def snapshot(self):
        view = self.store.read_snapshot(self.actor, at=self.now, max_records=10000, max_body_bytes=8*1024*1024)
        self.as_of = view['asOf']
        policy = self.store.contract.policy
        scopes = [key for key in policy.scopes if all(actor in policy.effective(key, timestamp(self.now))[0]['readers']
                  for actor in (self.actor, self.principal))]
        if not scopes:
            raise AppDenied('No intersecting app scopes')
        bindings = deepcopy(self.bindings)
        bindings['nodes'] = view['resources']
        graph = view['graph']
        resources = {item['resource']: key for key, item in self.store.contract.collections.items()}
        graph['nodes'] = [node for node in graph['nodes'] if self._readable(resources[view['resources'][node['id']]])]
        # Edges retain their existing host resource binding; new relationships are
        # never authorized by merely writing an app record.
        for actor in (self.actor, self.principal):
            boundary = ReadBoundary(policy, actor=actor, now=self.now, scopes=scopes, bindings=bindings)
            visible = boundary.graph(graph)
            graph = {'meta': view['graph']['meta'], 'nodes': visible['nodes'], 'edges': visible['edges']}
        self.kinds = {node['id']: self.store.contract.collections[resources[view['resources'][node['id']]]]['kind'] for node in graph['nodes']}
        self.revisions = {node['id']: view['revisions'][node['id']] for node in graph['nodes']}
        return graph, boundary

    def records(self, *, kind=None, address=None, q='', limit=50, offset=0, sort='title'):
        if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
            raise ValueError('Invalid pagination')
        graph, _ = self.snapshot()
        nodes = [node for node in graph['nodes'] if (kind is None or self.kinds[node['id']] == kind)
                 and (address is None or node['id'] == address)]
        tokens = q.casefold().split()
        nodes = [node for node in nodes if all(token in json.dumps(node, ensure_ascii=False).casefold() for token in tokens)]
        field = sort.removeprefix('-')
        nodes.sort(key=lambda node: (str(node.get(field, '')).casefold(), node['id']), reverse=sort.startswith('-'))
        items = [self._item(node) for node in nodes[offset:offset+limit]]
        if address is not None:
            if not items:
                raise AppDenied('Record unavailable')
            return items[0]
        return {'kind': kind, 'items': items, 'total': len(nodes), 'offset': offset, 'limit': limit, 'q': q,
                'fields': [], 'display': {'title': 'title', 'body': 'text'}}

    def _item(self, node):
        return {'address': node['id'], 'id': node['id'].partition(':')[2], 'kind': self.kinds[node['id']],
                'title': node.get('title', ''), 'summary': node.get('text', ''), 'markdown': node.get('text', ''),
                'values': deepcopy(node), 'revision': self.revisions[node['id']],
                'provenance': {'source': node.get('source'), 'review': node.get('evidence')},
                'fields': [], 'display': {'title': 'title', 'body': 'text'}}

    def revision(self, scope):
        graph, _ = self.snapshot()
        if scope in self.revisions:
            return self.revisions[scope]
        nodes = [node for node in graph['nodes'] if scope == self.kinds[node['id']]]
        # Native revisions also change on same-content corrections. Keep the
        # fingerprint scoped to visible records, never the global journal head.
        nodes.sort(key=lambda node: node['id'])
        return fingerprint([{'node': node, 'revision': self.revisions[node['id']]} for node in nodes])

    def context(self, request):
        graph, boundary = self.snapshot()
        snapshot = ContextSnapshot(graph, boundary=boundary, brain_revision=fingerprint(graph),
                                   as_of=self.as_of, recipe=self.recipe)
        return snapshot.basis() if request == {} else snapshot.compile(request)

    def _check_record(self, record, *, relations=True):
        if record is None:
            return
        collection = record['collection']
        if not self._readable(collection):
            raise AppDenied('Record outside app read grant')
        resource = self.store.contract.collections[collection]['resource']
        scope = self.store.contract.policy.resources[resource]['scope']
        node, _ = self.store.contract.project(record)
        bindings = deepcopy(self.bindings)
        bindings['nodes'][record['id']] = resource
        for actor in (self.actor, self.principal):
            boundary = ReadBoundary(self.store.contract.policy, actor=actor, now=self.now,
                                    scopes=[scope], bindings=bindings)
            if not boundary.permits_record('nodes', record['id'], node):
                raise AppDenied('Record provenance outside app read boundary')
        if relations:
            for edge in record.get('relations', []):
                if edge['target'] == record['id']:
                    continue
                target = self.store.get(edge['target'], self.actor, at=self.now)
                if not target or not target['record']:
                    raise AppDenied('Relationship unavailable')
                self._check_record(target['record'], relations=False)

    def mutate(self, body, *, kind=None, address=None, key, retract=False):
        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,200}', key):
            raise ValueError('Idempotency-Key required')
        allowed = {'record', 'expectedRevision', 'reason', 'evidence'}
        if not isinstance(body, dict) or set(body) != allowed:
            raise ValueError('Exact mutation fields required')
        record = deepcopy(body['record'])
        if retract:
            if record is not None or address is None:
                raise ValueError('Retraction requires an address and no replacement')
            current = self.store.get(address, self.actor, at=self.now)
            if not current or not current['record']:
                raise AppDenied('Record unavailable')
            collection = current['record']['collection']
        else:
            self.store.contract.validate_record(record)
            collection = record['collection']
            if address is not None and record['id'] != address:
                raise ValueError('Record address mismatch')
            if kind is not None and record['kind'] != kind:
                raise ValueError('Record kind mismatch')
            address = record['id']
        if not self._readable(collection):
            raise AppDenied('App collection unavailable')
        self._check_record(record)
        mutation = 'retract' if retract else 'create' if kind is not None else 'correct'
        if mutation == 'create' and body['expectedRevision'] is not None:
            raise ValueError('Create requires null expectedRevision')
        if mutation != 'create' and not isinstance(body['expectedRevision'], str):
            raise ValueError('Expected revision required')
        request = {'id': 'app:' + fingerprint([self.actor, self.app, key]), 'resource': self.store.contract.collections[collection]['resource'],
                   'record': address, 'mutation': mutation, 'expectedRevision': body['expectedRevision'],
                   'reason': body['reason'], 'evidence': body['evidence'], 'sourceResource': None}
        intent = fingerprint([request, record])
        with self.store.request_transaction(write=True):
            # A deterministic native proposal id provides durable retry semantics
            # for both pending proposals and committed receipts without a second ledger.
            proposal_id = request['id']
            old = self.store.dialect.execute('SELECT body FROM proposals WHERE id=?', (proposal_id,)).fetchone()
            if old:
                proposal = json.loads(old['body'])
                comparison = None if retract else proposal['record']
                if fingerprint([proposal['request'], comparison]) != intent or proposal['actor'] != self.principal:
                    raise AppConflict('Idempotency key reused with different intent')
            else:
                row = self.store._row(address)
                self._check_record(json.loads(row['body']) if row and not row['deleted'] else None)
                revision = row['revision'] if row else None
                if revision != body['expectedRevision']:
                    raise AppConflict('Changed since you opened')
                self.store.contract.decision(request, self.actor, 'propose', revision, at=self.now)
                # Both principals must read referenced relationships; native writer
                # checks the service, and this check keeps the running user in scope.
                for edge in (record or {}).get('relations', []):
                    target = self.store.get(edge['target'], self.actor, at=self.now)
                    if not target or not target['record']:
                        raise AppDenied('Relationship unavailable')
                    self._check_record(target['record'])
                result = self.store.propose(request, record, self.principal, at=self.now)
                self.store.dialect.execute('UPDATE proposals SET id=? WHERE id=?', (proposal_id, result['proposal']))
                raw = self.store.dialect.execute('SELECT body FROM proposals WHERE id=?', (proposal_id,)).fetchone()
                proposal = json.loads(raw['body'])
                proposal['id'] = proposal_id
                self.store.dialect.execute('UPDATE proposals SET body=? WHERE id=?', (json.dumps(proposal), proposal_id))
            # Current policy is evaluated on retries too. App services never review.
            for actor in (self.actor, self.principal):
                self.store.contract.decision(request, actor, 'propose', body['expectedRevision'], at=self.now)
            if collection not in self.grant['owned']:
                return {'outcome': 'proposed', 'revision': body['expectedRevision'], 'receipt': proposal_id}
            self.store.contract.decision(request, self.actor, 'commit', body['expectedRevision'], at=self.now, proposed_by=self.principal)
            receipt = self.store.commit(proposal_id, self.principal, at=self.now)
            self._check_record(receipt['before'])
            self._check_record(receipt['after'])
            result = {'outcome': 'committed', 'revision': receipt['revision'], 'receipt': receipt}
            if len(encode(result)) > 4*1024*1024:
                raise ValueError('App response exceeds budget')
            return result
