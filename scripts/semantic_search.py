"""Opt-in hybrid pilot. Ranking scores never certify factual support."""
from copy import deepcopy

from context_bundle import ContextError, _evidence_gaps, encode
from context_search import match_details, score_record, terms
from knowledge_policy import timestamp


def search(nodes, edges, request, authorization, projection, manifest, *, basis, graph_hops=0):
    if type(graph_hops) is not int or graph_hops not in (0, 1):
        raise ContextError('Semantic graph expansion supports zero or one hop')
    principal = authorization['principal']
    wanted = set(terms(request['query']))
    semantic = projection.rank(nodes, basis, principal, request['query'], manifest)
    lexical = []
    by_id = {node['id']: node for node in nodes}
    for node in nodes:
        matched, score = score_record(node, wanted)
        if matched:
            lexical.append((-len(matched), -score, node['id']))
    lexical.sort()
    weights, modes, ranks = {}, {}, {}
    for mode, identities in [('lexical', [row[2] for row in lexical]),
                             ('semantic', [row['recordId'] for row in semantic])]:
        for rank, identity in enumerate(identities, 1):
            weights[identity] = weights.get(identity, 0) + 1 / (60 + rank)
            modes.setdefault(identity, []).append(mode)
            ranks.setdefault(identity, {})[mode] = rank
    if graph_hops:
        seeds = set(sorted(weights, key=lambda identity: (-weights[identity], identity))[:5])
        for edge in sorted(edges, key=lambda e: (e['source'], e['target'], e.get('rel', ''))):
            source, target = edge['source'], edge['target']
            if source not in by_id or target not in by_id:
                continue
            for seed, identity in ((source, target), (target, source)):
                if seed in seeds and identity not in seeds:
                    if 'graph' not in modes.setdefault(identity, []):
                        weights[identity] = weights.get(identity, 0) + 1 / 120
                        modes[identity].append('graph')
    ordered = sorted(weights, key=lambda identity: (identity != request['query'], -weights[identity], identity))
    semantic_by_id = {row['recordId']: row for row in semantic}
    result = {'protocolVersion': '1.0', 'method': 'authorized-hybrid-pilot/v1',
              'request': deepcopy(request), 'authorization': deepcopy(authorization), 'matches': [],
              'gaps': [{'state': 'not-assessed', 'reason': 'semantic-no-answer-calibration-not-approved'}],
              'truncation': [], 'coverage': {'state': 'not-assessed'}}

    def fits(value):
        return len(encode({**value, 'truncation': ['maxBytes', 'maxMatches']})) <= request['budget']['maxBytes']

    if not fits(result):
        raise ContextError('maxBytes cannot hold the search response envelope')
    for identity in ordered:
        if len(result['matches']) >= request['budget']['maxMatches']:
            result['truncation'] = sorted(set(result['truncation']) | {'maxMatches'})
            break
        node = by_id[identity]
        matched, _ = score_record(node, wanted)
        match = {'record': deepcopy(node), 'matchedTerms': matched, 'score': weights[identity],
                 'gaps': _evidence_gaps(node, identity, timestamp(request['asOf']))}
        if request.get('includeDetails', False):
            lexical_details = match_details(node, wanted, request)
            row = semantic_by_id.get(identity)
            chunk = deepcopy(row['chunk']) if row else None
            if chunk:
                locator = chunk['locator']
                end = min(locator['end'], locator['start'] + 320)
                excerpt = {'text': node[locator['field']][locator['start']:end],
                           'locator': {**locator, 'end': end},
                           'truncated': locator['start'] > 0 or end < len(node[locator['field']])}
            else:
                excerpt = lexical_details['excerpt']
            match['details'] = {'format': 'hybrid-search-details/v1', 'recordId': identity,
                'matchedModes': modes[identity], 'source': lexical_details['source'],
                'excerpt': excerpt, 'revision': lexical_details['revision'],
                'chunk': {key: chunk[key] for key in ('id', 'locator', 'recordSha256')} if chunk else None,
                'ranking': {'kind': 'reciprocal-rank-fusion', 'rankConstant': 60,
                            'ranks': ranks.get(identity, {}), 'graphContribution': 1 / 120 if 'graph' in modes[identity] else 0,
                            'cosine': row['cosine'] if row else None, 'isEvidenceConfidence': False}}
        candidate = deepcopy(result)
        candidate['matches'].append(match)
        if fits(candidate):
            result = candidate
        else:
            result['truncation'] = sorted(set(result['truncation']) | {'maxBytes'})
    return result
