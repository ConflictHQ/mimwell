"""Bounded lexical discovery over an already-authorized context snapshot.

Ranks are deterministic keyword matches, never relevance probabilities or evidence
support. No corpus-wide statistics, vectors, remote reads or imported grants.
"""
from copy import deepcopy
import hashlib
import re
import unicodedata

from context_bundle import ContextError, _evidence_gaps, _object, encode, validate_request
from context_access import record_paths
from knowledge_policy import timestamp


METHOD = 'authorized-lexical/v1'
FIELDS = {'id': 3, 'title': 4, 'text': 1}
TOKEN = re.compile(r'[^\W_]+', re.UNICODE)
DETAIL_FORMAT = 'search-details/v1'
EXCERPT_CHARS = 320


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
    fields = ('protocolVersion', 'query', 'scopes', 'recipe', 'asOf', 'revisions', 'budget')
    if isinstance(request, dict) and 'includeDetails' in request:
        fields += ('includeDetails',)
    _object(request, fields, 'search request')
    if 'includeDetails' in request and type(request['includeDetails']) is not bool:
        raise ContextError('includeDetails must be a boolean')
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


def _excerpt_anchor(text, wanted):
    """Keep original offsets while matching normalized words and combining marks."""
    start = None
    for offset, char in enumerate(text):
        if char.isalnum() or unicodedata.category(char).startswith('M'):
            if start is None:
                start = offset
        elif start is not None:
            if wanted.intersection(terms(text[start:offset])):
                return start
            start = None
    if start is not None and wanted.intersection(terms(text[start:])):
        return start
    return 0


def match_details(node, wanted, request):
    """Describe only the authorized record already included in the match.

    Excerpt positions address that record's text, not unverified file offsets.
    The digest identifies observed content, never an authority revision or a
    statement that the record's evidence supports the query.
    """
    text = node.get('text') if isinstance(node.get('text'), str) else ''
    first = _excerpt_anchor(text, wanted)
    start = max(0, first - EXCERPT_CHARS // 4)
    end = min(len(text), start + EXCERPT_CHARS)
    fields = []
    for field, weight in FIELDS.items():
        value = node.get(field, '')
        matched = sorted(wanted & set(terms(value))) if isinstance(value, str) else []
        if matched:
            fields.append({'field': field, 'terms': matched, 'weight': weight,
                           'contribution': weight * len(matched)})
    return {
        'format': DETAIL_FORMAT,
        'recordId': node['id'],
        'matchedModes': ['lexical'],
        'source': {'paths': sorted(record_paths(node))} if record_paths(node) else None,
        'excerpt': {'text': text[start:end], 'locator': {'recordId': node['id'], 'field': 'text',
                    'start': start, 'end': end, 'unit': 'unicode-code-point'},
                    'truncated': start > 0 or end < len(text)},
        'revision': {'snapshot': request['revisions']['brain'],
                     'recordSha256': hashlib.sha256(encode(node)).hexdigest()},
        'ranking': {'kind': 'keyword-field-weight', 'fields': fields,
                    'order': ['matched-term-count-desc', 'field-weight-sum-desc', 'record-id-asc'],
                    'isEvidenceConfidence': False},
    }


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
        match = {'record': node, 'matchedTerms': matched, 'score': -negative_score,
                 'gaps': _evidence_gaps(node, node['id'], as_of)}
        if request.get('includeDetails', False):
            match['details'] = match_details(node, wanted, request)
        candidate['matches'].append(match)
        if fits(candidate):
            result = candidate
        else:
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
    return deepcopy(result)
