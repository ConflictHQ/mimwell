"""Source-linked semantic projections over an already authorized snapshot.

The vector role owns vector placement. This module owns bounded chunk locators
and their observed basis, never records, permissions or evidence confidence.
"""
from copy import deepcopy
import hashlib
import math

from context_bundle import ContextError, encode
from context_access import record_paths
from vector_role import f32, index_digest, namespace

FORMAT = 'semantic-chunks/v1'
CHUNKER = 'token-offset-window/v1'
MAX_CHUNKS = 10000
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_TOKENS = 256
OVERLAP = 32


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def material_basis(nodes, basis, principal):
    """Only the admitted material can influence a namespace's basis or ranks."""
    return {'basis': deepcopy(basis), 'principal': principal,
            'records': {node['id']: digest(node) for node in sorted(nodes, key=lambda n: n['id'])}}


def chunks(nodes, provider):
    result = []
    seen = set()
    if len(encode(nodes)) > MAX_SOURCE_BYTES:
        raise ContextError('Semantic source material exceeds its limit')
    for node in sorted(nodes, key=lambda n: n['id']):
        if node['id'] in seen:
            raise ContextError('Semantic source identities are ambiguous')
        seen.add(node['id'])
        field = 'text' if isinstance(node.get('text'), str) and node['text'] else 'title'
        text = node.get(field, '')
        if not isinstance(text, str) or not text:
            continue
        spans = provider.offsets(text)
        if not spans:
            continue
        if any(type(a) is not int or type(b) is not int or not 0 <= a < b <= len(text)
               for a, b in spans):
            raise ContextError('Semantic tokenizer returned invalid source offsets')
        if any(a[0] > b[0] or a[1] > b[1] for a, b in zip(spans, spans[1:])):
            raise ContextError('Semantic tokenizer returned unordered source offsets')
        for first in range(0, len(spans), MAX_TOKENS - OVERLAP):
            last = min(len(spans), first + MAX_TOKENS)
            start, end = spans[first][0], spans[last - 1][1]
            locator = {'recordId': node['id'], 'field': field, 'start': start, 'end': end,
                       'unit': 'unicode-code-point'}
            chunk = {'id': 'chunk:' + digest(locator), 'recordId': node['id'],
                     'recordSha256': digest(node), 'source': {'paths': sorted(record_paths(node))},
                     'locator': locator, 'text': text[start:end]}
            result.append(chunk)
            if len(result) > MAX_CHUNKS:
                raise ContextError('Semantic chunk limit exceeded')
            if last == len(spans):
                break
    return result


def checked_vectors(values, count, dimension):
    if len(values) != count or any(len(row) != dimension for row in values):
        raise ContextError('Semantic provider returned incompatible vectors')
    result = []
    for row in values:
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in row):
            raise ContextError('Semantic provider returned nonfinite vectors')
        length = math.hypot(*row)
        if not math.isfinite(length) or length <= 0:
            raise ContextError('Semantic provider returned a zero vector')
        result.append(f32([v / length for v in row]))
    return result


class ChunkProjection:
    """Host-selected vector store plus a separately persisted, digest-bound manifest.

    Updating vectors before the manifest is safe: a torn update refuses reads.
    Callers persist the returned manifest in private host storage. Refresh can
    reuse unchanged chunks; deletion replaces the audience's complete index.
    """

    def __init__(self, store, provider, *, realm):
        if not isinstance(realm, str) or not realm:
            raise ContextError('Semantic projection requires an explicit realm')
        self.store, self.provider, self.realm = store, provider, realm

    def _name(self, principal):
        return namespace(self.realm, principal)

    def _compatible(self, manifest, principal):
        return (isinstance(manifest, dict) and manifest.get('format') == FORMAT
                and manifest.get('namespace') == self._name(principal)
                and manifest.get('realm') == self.realm
                and manifest.get('provider') == self.provider.binding
                and manifest.get('chunker') == {'id': CHUNKER, 'tokens': MAX_TOKENS, 'overlap': OVERLAP})

    def _stored(self, manifest):
        index = self.store.read(manifest['namespace'])
        if (index is None or index_digest(index) != manifest['indexSha256']
                or index['embedder'] != {'id': digest(self.provider.binding), 'dim': self.provider.dim}
                or len(set(index['node_ids'])) != len(index['node_ids'])
                or set(index['node_ids']) != {chunk['id'] for chunk in manifest['chunks']}):
            raise ContextError('Semantic index is unavailable or mismatched')
        return index

    def refresh(self, nodes, basis, principal, previous=None):
        wanted = sorted(chunks(nodes, self.provider), key=lambda chunk: chunk['id'])
        old = {}
        if self._compatible(previous, principal):
            try:
                stored = self._stored(previous)
                prior = {chunk['id']: chunk for chunk in previous['chunks']}
                old = {identity: (prior[identity], vector) for identity, vector
                       in zip(stored['node_ids'], stored['vectors'])}
            except (ValueError, KeyError, TypeError):
                old = {}
        missing = [chunk for chunk in wanted if chunk['id'] not in old
                   or old[chunk['id']][0]['text'] != chunk['text']]
        vectors = checked_vectors(self.provider.embed([chunk['text'] for chunk in missing]),
                                  len(missing), self.provider.dim) if missing else []
        new = dict(zip((chunk['id'] for chunk in missing), vectors))
        index = {'version': 2, 'embedder': {'id': digest(self.provider.binding), 'dim': self.provider.dim},
                 'node_ids': [chunk['id'] for chunk in wanted],
                 'node_text_sha256': [digest(chunk) for chunk in wanted],
                 'vectors': [new[chunk['id']] if chunk['id'] in new else old[chunk['id']][1]
                             for chunk in wanted]}
        name = self._name(principal)
        self.store.replace(name, index)
        manifest = {'format': FORMAT, 'namespace': name, 'realm': self.realm,
                    'provider': deepcopy(self.provider.binding),
                    'chunker': {'id': CHUNKER, 'tokens': MAX_TOKENS, 'overlap': OVERLAP},
                    'material': material_basis(nodes, basis, principal),
                    'chunks': wanted, 'indexSha256': index_digest(index)}
        self._stored(manifest)
        return manifest, {'embeddedChunks': len(missing), 'retainedChunks': len(wanted) - len(missing)}

    def rank(self, nodes, basis, principal, query, manifest):
        if (not self._compatible(manifest, principal)
                or manifest.get('material') != material_basis(nodes, basis, principal)
                or manifest.get('chunks') != sorted(chunks(nodes, self.provider), key=lambda chunk: chunk['id'])):
            raise ContextError('Semantic projection does not match the authorized source basis')
        stored = self._stored(manifest)
        query_vector = checked_vectors(self.provider.embed_query(query), 1, self.provider.dim)[0]
        by_id = dict(zip(stored['node_ids'], stored['vectors']))
        best = {}
        for chunk in manifest['chunks']:
            score = sum(a * b for a, b in zip(by_id[chunk['id']], query_vector))
            candidate = {'recordId': chunk['recordId'], 'cosine': score, 'chunk': deepcopy(chunk)}
            previous = best.get(chunk['recordId'])
            if previous is None or (-score, chunk['id']) < (-previous['cosine'], previous['chunk']['id']):
                best[chunk['recordId']] = candidate
        return sorted(best.values(), key=lambda row: (-row['cosine'], row['recordId']))
