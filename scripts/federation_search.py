"""Bounded cross-brain discovery using source-side read and publication checks.

No merged authority, result cache, automatic membership, or entity equivalence.
Fresh authenticated hosts reconstruct sources per request; snapshots are read points.
"""
from copy import deepcopy

from brain_federation import FederationError, fields, text
from context_bundle import _evidence_gaps, encode
from context_search import METHOD, score_record, terms
from knowledge_policy import timestamp

FEDERATED_METHOD = 'federated-authorized-lexical/v1'


def validate_query(query):
    if not isinstance(query, str) or not 1 <= len(query) <= 256 or not 1 <= len(terms(query)) <= 32:
        raise FederationError('Search requires 1–32 terms in at most 256 characters')


def positive(value):
    if type(value) is not int or value < 1:
        raise FederationError('Search budgets must be positive integers')


def source_search(source, query, *, revision, audience, consumer, now, max_matches, max_bytes):
    validate_query(query)
    positive(max_matches)
    positive(max_bytes)
    if consumer != source._consumer or now != source._boundary.now:
        return {'status': 'unavailable', 'reason': 'unavailable'}
    if revision != source.revision:
        return {'status': 'unavailable', 'reason': 'revision-changed'}
    ranked = []
    wanted = set(terms(query))
    for address in source._records:
        # Includes evidence/publication/reviewer checks and structured-store receipts.
        # No denied record contributes terms, scores, counts or result metadata.
        outcome = source.resolve(address, revision=revision, audience=audience, consumer=consumer, now=now)
        if outcome['status'] != 'resolved':
            continue
        record = outcome['record']
        matched, score = score_record(record, wanted)
        if matched:
            ranked.append((-len(matched), -score, address, {
                'record': record, 'provenance': outcome['provenance'], 'matchedTerms': matched, 'score': score,
                'gaps': _evidence_gaps(record, address, timestamp(now))}))
    ranked.sort(key=lambda row: row[:3])
    result = {'status': 'searched', 'method': METHOD, 'matches': [], 'truncation': []}

    def fits(value):
        return len(encode({**value, 'truncation': ['maxBytes', 'maxMatches']})) <= max_bytes

    if not fits(result):
        return {'status': 'unavailable', 'reason': 'maxBytes'}
    for *_, match in ranked:
        if len(result['matches']) >= max_matches:
            result['truncation'] = sorted(set(result['truncation']) | {'maxMatches'})
            break
        candidate = {**result, 'matches': [*result['matches'], match]}
        if fits(candidate):
            result = candidate
        else:
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
    return deepcopy(result)


def validate_request(request):
    fields(request, ('protocolVersion', 'query', 'sources', 'budget'))
    if request['protocolVersion'] != '1.0' or not isinstance(request['sources'], list):
        raise FederationError('Unsupported federation search request')
    validate_query(request['query'])
    fields(request['budget'], ('maxSources', 'maxMatches', 'maxBytes'))
    for value in request['budget'].values():
        positive(value)
    selected = {}
    for source in request['sources']:
        fields(source, ('participant', 'realm', 'revision'))
        for value in source.values():
            text(value)
        identity = (source['participant'], source['realm'])
        if identity in selected and selected[identity] != source:
            raise FederationError('One source cannot select two revisions')
        selected[identity] = deepcopy(source)
    return [selected[key] for key in sorted(selected)]


def federated_search(resolver, request):
    request = deepcopy(request)
    sources = validate_request(request)
    budget = request['budget']
    result = {'protocolVersion': '1.0', 'method': FEDERATED_METHOD, 'federation': resolver.federation,
              'authorization': resolver.authorization, 'query': request['query'],
              'sources': [], 'matches': [], 'truncation': [], 'coverage': {'state': 'not-assessed'}}
    reasons = ['maxBytes', 'maxMatches', 'maxSources', 'sourcePartial']

    def fits(value):
        return len(encode({**value, 'truncation': reasons})) <= budget['maxBytes']

    if not fits(result):
        raise FederationError('Search budget cannot hold its envelope')
    if len(sources) > budget['maxSources']:
        result['truncation'].append('maxSources')
    ranked = []
    collected, limited = resolver._collect(sources[:budget['maxSources']],
        lambda source: resolver.search_source(source, request['query'], max_matches=budget['maxMatches'],
            max_bytes=budget['maxBytes']), max_bytes=budget['maxBytes'])
    if limited:
        result['truncation'].append('maxBytes')
    for source, outcome in collected:
        receipt = {'source': source, 'status': outcome['status']}
        if outcome['status'] == 'searched':
            receipt['truncation'] = outcome['truncation']
            if outcome['truncation']:
                result['truncation'] = sorted(set(result['truncation']) | {'sourcePartial'})
        else:
            receipt['reason'] = outcome['reason']
        candidate = {**result, 'sources': [*result['sources'], receipt]}
        if not fits(candidate):
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
            continue  # Never emit a hit whose source status/revision was omitted.
        result = candidate
        for match in outcome.get('matches', []):
            target = {**source, 'address': match['record']['id']}
            if (source['participant'], source['realm']) in resolver._served:
                # The body stays in this host; the match names the record only.
                match = {**match, 'record': {'id': match['record']['id'], 'kind': match['record']['kind']}}
            ranked.append((-len(match['matchedTerms']), -match['score'], source['participant'],
                           source['realm'], target['address'], {'target': target, **match}))
    ranked.sort(key=lambda row: row[:5])
    for *_, match in ranked:
        if len(result['matches']) >= budget['maxMatches']:
            result['truncation'] = sorted(set(result['truncation']) | {'maxMatches'})
            break
        candidate = {**result, 'matches': [*result['matches'], match]}
        if fits(candidate):
            result = candidate
        else:
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
    log_served_reads(resolver, collected, result)
    return deepcopy(result)


def log_served_reads(resolver, collected, result):
    """One access-log entry per served source read, before the result leaves the host.

    Entries name the actor, source, outcome and released addresses, never a body.
    A failed log write refuses the whole response.
    """
    for source, outcome in collected:
        if (source['participant'], source['realm']) not in resolver._served:
            continue
        entry = {'at': resolver.authorization['evaluatedAt'], 'actor': resolver.authorization['principal'],
                 'federation': resolver.federation, 'operation': 'search', 'source': deepcopy(source),
                 'status': outcome['status'], 'reason': outcome.get('reason'),
                 'released': [m['target']['address'] for m in result['matches'] if m['target'] == {
                     **source, 'address': m['target']['address']}]}
        try:
            resolver._access_log(entry)
        except Exception:
            raise FederationError('Served source access log unavailable') from None
