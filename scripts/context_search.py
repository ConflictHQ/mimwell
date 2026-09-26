"""Bounded lexical discovery over an already-authorized context snapshot.

Ranks are deterministic keyword matches, never relevance probabilities or evidence
support. No corpus-wide statistics, vectors, remote reads or imported grants.
"""
from copy import deepcopy
import re
import unicodedata

from context_bundle import ContextError, _evidence_gaps, _object, encode, validate_request
from knowledge_policy import timestamp


METHOD = 'authorized-lexical/v1'
FIELDS = {'id': 3, 'title': 4, 'text': 1}
TOKEN = re.compile(r'[^\W_]+', re.UNICODE)


def terms(text):
    return sorted(set(TOKEN.findall(unicodedata.normalize("NFKC", text).casefold())))



def score_record(node, wanted):
    """Shared deterministic keyword score; callers authorize before calling."""
    matched, score = set(), 0
    for field, weight in FIELDS.items():
        value = node.get(field, '')
        if not isinstance(value, str):
            continue
        found = wanted.intersection(terms(value))
        matched.update(found)
        score += weight * len(found)
    return sorted(matched), score


def validate_search(request):
    _object(request, ('protocolVersion', 'query', 'scopes', 'recipe', 'asOf', 'revisions', 'budget'), 'search request')
    query = request['query']
    if not isinstance(query, str) or not 1 <= len(query) <= 256 or not 1 <= len(terms(query)) <= 32:
        raise ContextError('Search requires 1–32 terms in at most 256 characters')
    budget = request['budget']
    _object(budget, ('maxMatches', 'maxBytes'), 'search budget')
    # Reuse the existing closed basis/scope validation and integer budget rules.
    validate_request({**{k: request[k] for k in ('protocolVersion', 'scopes', 'recipe', 'asOf', 'revisions')},
        'target': {'type': 'task', 'id': 'search'}, 'budget': {
            'maxNodes': budget['maxMatches'], 'maxBytes': budget['maxBytes'],
            'maxEdges': 0, 'maxHops': 0, 'maxReferences': 0, 'maxQuestions': 0}})


def search(nodes, request, authorization, freshness=None):
    """All input rows must already be policy-filtered; return copies within bounds."""
    wanted = set(terms(request['query']))
    ranked = []
    for node in nodes:
        matched, score = score_record(node, wanted)
        if matched:
            ranked.append((-len(matched), -score, node['id'], node, sorted(matched)))
    ranked.sort(key=lambda row: row[:3])
    result = {'protocolVersion': '1.0', 'method': METHOD, 'request': deepcopy(request),
              'authorization': deepcopy(authorization), 'matches': [], 'gaps': [],
              'truncation': [], 'coverage': {'state': 'not-assessed'}}
    if freshness is not None:
        result['projectionFreshness'] = {key: value for key, value in freshness.items() if key != 'basis'}
        if freshness['state'] != 'current':
            result['gaps'].append({'projection': freshness['scope'], 'state': freshness['state'],
                                   'reason': freshness['reason']})
    if not ranked:
        result['gaps'].append({'state': 'unknown', 'reason': 'no-authorized-lexical-match'})

    def fits(candidate):
        return len(encode({**candidate, 'truncation': ['maxBytes', 'maxMatches']})) <= request['budget']['maxBytes']

    if not fits(result):
        raise ContextError('maxBytes cannot hold the search response envelope')
    as_of = timestamp(request['asOf'])
    for _, negative_score, _, node, matched in ranked:
        if len(result['matches']) >= request['budget']['maxMatches']:
            result['truncation'] = sorted(set(result['truncation']) | {'maxMatches'})
            break
        candidate = deepcopy(result)
        candidate['matches'].append({'record': node, 'matchedTerms': matched, 'score': -negative_score,
                                    'gaps': _evidence_gaps(node, node['id'], as_of)})
        if fits(candidate):
            result = candidate
        else:
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
    return deepcopy(result)
