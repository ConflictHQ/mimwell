#!/usr/bin/env python3
"""Embed the compiled brain into a vector index for semantic retrieval (#27).

Lexical FTS/substring search (#4, brain_store.search) answers "which nodes
contain this token". Semantic retrieval answers "which nodes are ABOUT this",
even when they share no literal words — materially better agent answers on
AI/research-heavy projects. This script builds the vector index that the hybrid
retrieval path in brain_store.py reads.

WHAT IT EMBEDS
--------------
One vector per brain node, over the SAME text the lexical path matches:
`brain_store.search_haystack(node)` (id + title + text + kind, lowercased). Reusing
the single haystack definition keeps the lexical and semantic views of a node in
lockstep — they can never drift apart, and there is one place to change what
"the text of a node" means.

THE INDEX (gitignored, rebuilt — never committed)
-------------------------------------------------
A portable JSON sidecar next to brain.db at app/brain.vec.json:

    {
      "version": 2,
      "embedder": {"id": "local-charngram-hash@1", "dim": 1024},
      "node_text_sha256": ["<normalized text sha256>", ...],
      "node_ids": ["concept:alpha", ...],          # sorted, parallel to vectors
      "vectors":  [[...], ...]                      # L2-normalized, sparse-as-dense
    }

It is gitignored and rebuilt from brain.json (same posture as app/brain.db) — it
is a derived query cache, not source. brain_store loads it lazily; a missing or
empty, legacy or malformed index falls back to pure lexical search cleanly.
A read verifies the embedder identity/dimension and each candidate's current text
hash. Changed/removed records cannot contribute obsolete vector scores. Rebuild
with `make embed` and reopen/reset readers after a publication. This validates the
loaded backend snapshot, not upstream collection age or authorization.

PLUGGABLE EMBEDDER (config-only swap)
-------------------------------------
The embedder is selected from client.config.json -> "semantic" (mirrors the
recordings.diarization provider seam):

    "semantic": {
      "embedder": {
        "module": "",            # external provider module (empty -> local default)
        "class":  "",            # provider class exposing embed(list[str])->list[vec]
        "model":  "",            # optional model id, passed if the provider takes it
        "apiKeyEnv": "",         # documented; this script never reads the key itself
        "dim": 1024              # local default vector width
      }
    }

When `module`/`class` are empty (the default), a DETERMINISTIC LOCAL embedder is
used: a char-ngram hashing TF vectorizer, STDLIB ONLY, no API key, no network.
It builds and tests with zero external deps. An external provider is dynamically
imported and is a clean no-op fall-back to the local embedder when unconfigured
or unavailable — exactly the diarization pattern.

DETERMINISM CAVEAT
------------------
The index is reproducible GIVEN A FIXED EMBEDDER. The local default is fully
deterministic (a pure hash of the text — same input, same vector, forever) and
carries a version tag (`local-charngram-hash@1`); bump the tag if the algorithm
ever changes so a stale index is detectable. An EXTERNAL provider's determinism
is only as strong as its pinned model version — pin the model and record it in
the `model` field. The index records its embedder id so a consumer can detect a
mismatch and rebuild.

Gated by features.semantic_search (default false): when off this is a clean
no-op (exit 0) — the brain ships without the sidecar and retrieval stays lexical.

Run from anywhere:  python3 scripts/embed-brain.py
"""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import sys
import tempfile
from typing import Any, Sequence

from brain_store import search_fingerprint, search_haystack  # single source of the node text
from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAIN_JSON = os.path.join(ROOT, "app", "brain.json")
# The vector index sidecar — next to brain.db, same gitignored/rebuilt posture.
BRAIN_VEC = os.path.join(ROOT, "app", "brain.vec.json")

# Local-default knobs. The char-ngram width and vector dimension are part of the
# embedder identity: changing either changes every vector, so they are pinned in
# the embedder id below and the index records which id produced it.
_NGRAM = 3
_DEFAULT_DIM = 1024
_LOCAL_ID = "local-charngram-hash@1"


# ----------------------------------------------------------------------------
# Embedder interface
# ----------------------------------------------------------------------------
#
# An embedder is anything with `id`, `dim`, and `embed(texts) -> list[vector]`
# returning one L2-normalized float vector per input text (a vector is a plain
# list[float], so the index is JSON-portable and stdlib-only). Two embedders
# ship: the deterministic local default, and a thin adapter over an externally
# configured provider. Both are selected — never hardcoded — from config.


class _Embedder:
    """Uniform embed API. `id` tags the index so a stale/mismatched index is
    detectable; `dim` is the vector width."""

    id: str = "abstract"
    dim: int = 0

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise NotImplementedError


class LocalCharNgramEmbedder(_Embedder):
    """Deterministic, stdlib-only, no-API-key default.

    Each text is lowercased and hashed into a fixed-width bag of character
    n-grams: every `_NGRAM`-char window (plus single tokens, so short words still
    contribute) is hashed (BLAKE2b, seeded by the bucket index) into one of `dim`
    buckets and its term frequency accumulated, then the vector is L2-normalized.

    This is the hashing-trick / feature-hashing TF vectorizer: it captures
    sub-word overlap (so "embedding" and "embeddings" land near each other and a
    query shares mass with morphological variants a token FTS would miss) while
    being a PURE FUNCTION of the text — same input, same vector, on any machine,
    forever. That is the whole determinism guarantee for the local path.
    """

    id = _LOCAL_ID

    def __init__(self, dim: int = _DEFAULT_DIM):
        self.dim = int(dim) if dim else _DEFAULT_DIM

    def _features(self, text: str):
        """Yield the char-ngram + token features of one text (lowercased)."""
        t = (text or "").lower()
        # Whole tokens: a short word ("kg", "sql") is its own feature so it is not
        # lost to the n-gram window.
        for tok in t.split():
            if tok:
                yield tok
        # Character n-grams over the whitespace-collapsed string capture sub-word
        # overlap across token boundaries deterministically.
        collapsed = " ".join(t.split())
        for i in range(len(collapsed) - _NGRAM + 1):
            yield collapsed[i:i + _NGRAM]

    def _bucket(self, feature: str) -> int:
        """Stable hash of a feature into [0, dim). hashlib (not Python's salted
        hash()) so the bucket is identical across processes and machines."""
        h = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(h, "big") % self.dim

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dim
            for feat in self._features(text):
                vec[self._bucket(feat)] += 1.0
            norm = math.sqrt(sum(v * v for v in vec))
            if norm:
                vec = [v / norm for v in vec]
            out.append(vec)
        return out


class _ProviderEmbedder(_Embedder):
    """Adapter over an externally configured embedding provider (dynamically
    imported, like the diarization provider). The provider class must expose
    `embed(list[str]) -> list[vector]`; vectors are L2-normalized here so the
    index is provider-agnostic and cosine similarity is a plain dot product.

    `id` records the provider + model so a later index read can detect that the
    embedder changed and rebuild. This is never the default — it is selected only
    when `semantic.embedder.module`/`class` are set AND import + init succeed;
    otherwise the caller falls back to the local default cleanly."""

    def __init__(self, provider: Any, model: str, dim: int, tag: str):
        self._provider = provider
        self._model = model
        self.dim = dim
        self.id = tag

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        try:
            raw = self._provider.embed(list(texts), model=self._model or None)
        except TypeError:
            raw = self._provider.embed(list(texts))
        if not valid_vectors(raw, len(texts), self.dim, normalized=False):
            raise ValueError("Embedding provider returned invalid values or dimensions")
        out: list[list[float]] = []
        for v in raw:
            v = [float(x) for x in v]
            norm = math.hypot(*v)
            out.append([x / norm for x in v] if norm else v)
        return out


# ----------------------------------------------------------------------------
# Embedder selection — one place, driven by settings.semantic.embedder
# ----------------------------------------------------------------------------


def embedder_config() -> dict:
    """The `semantic.embedder` block, with env overrides for the provider seam
    (mirrors diarize-transcripts.py). All keys optional; empty -> local default."""
    block: dict = {}
    sem = settings.semantic  # defaulted section (config.py _DEFAULTS["semantic"])
    if "embedder" in sem:
        block = dict(sem.embedder)  # MappingProxyType or default dict -> plain dict
    return {
        "module": os.environ.get("EMBED_PROVIDER_MODULE") or block.get("module") or "",
        "class": os.environ.get("EMBED_PROVIDER_CLASS") or block.get("class") or "",
        "model": os.environ.get("EMBED_MODEL") or block.get("model") or "",
        "dim": int(block.get("dim") or _DEFAULT_DIM),
    }


def _load_provider(module_name: str, class_name: str):
    """Import + instantiate the configured provider, or None when unavailable —
    a clean no-op fall-back to the local default (the diarization pattern)."""
    if not module_name or not class_name:
        return None
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    cls = getattr(module, class_name, None)
    if cls is None:
        return None
    try:
        return cls()
    except Exception as e:  # provider may need credentials/config to init
        print(f"embedder {class_name} could not initialize: {e}", flush=True)
        return None


def get_embedder() -> _Embedder:
    """The configured embedder: the external provider when set + importable,
    else the deterministic local default. Selection is CONFIG-ONLY — swapping
    embedders never edits this code."""
    cfg = embedder_config()
    provider = _load_provider(cfg["module"], cfg["class"])
    if provider is not None:
        tag = f"{cfg['module']}.{cfg['class']}" + (f"@{cfg['model']}" if cfg["model"] else "")
        dim = getattr(provider, "dim", 0) or cfg["dim"]
        return _ProviderEmbedder(provider, cfg["model"], dim, tag)
    return LocalCharNgramEmbedder(cfg["dim"])


# ----------------------------------------------------------------------------
# Index build / load
# ----------------------------------------------------------------------------


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in embedding input")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-finite JSON value in embedding input")


def _read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)


def _load_nodes(brain_path: str) -> list[dict]:
    data = _read_json(brain_path)
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list):
        raise ValueError("Embedding source requires an explicit nodes array")
    nodes = data["nodes"]
    if any(not isinstance(n, dict) or not isinstance(n.get("id"), str) or not n["id"].strip() for n in nodes):
        raise ValueError("Embedding nodes require nonempty string IDs")
    if len({n["id"] for n in nodes}) != len(nodes):
        raise ValueError("Duplicate embedding node ID")
    # Refuse overflow/non-finite numbers throughout the source, not only vectors.
    json.dumps(data, allow_nan=False)
    return sorted(nodes, key=lambda n: n["id"])


def valid_vectors(vectors, count, dim, *, normalized=True):
    """Reject mismatched counts/widths, nonnumeric values and invalid cosine norms."""
    if type(dim) is not int or dim <= 0 or not isinstance(vectors, list) or len(vectors) != count:
        return False
    for vector in vectors:
        if not isinstance(vector, list) or len(vector) != dim:
            return False
        try:
            if any(type(value) not in (int, float) or not math.isfinite(value) for value in vector):
                return False
            norm = math.hypot(*vector)
        except OverflowError:
            return False
        if not math.isfinite(norm):
            return False
        if normalized and norm != 0 and not math.isclose(norm, 1.0, rel_tol=1e-6, abs_tol=1e-6):
            return False
    return True


def valid_index(index):
    if not isinstance(index, dict) or index.get("version") != 2:
        return False
    descriptor = index.get("embedder")
    ids, hashes = index.get("node_ids"), index.get("node_text_sha256")
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get("id"), str) or not descriptor["id"]:
        return False
    if not isinstance(ids, list) or any(not isinstance(n, str) or not n.strip() for n in ids):
        return False
    if len(set(ids)) != len(ids) or ids != sorted(ids):
        return False
    if not isinstance(hashes, list) or len(hashes) != len(ids) or any(
            not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h) for h in hashes):
        return False
    return valid_vectors(index.get("vectors"), len(ids), descriptor.get("dim"))


def build_index(brain_path: str = BRAIN_JSON, embedder: _Embedder | None = None) -> dict:
    """Build a validated index bound to its embedder and every indexed text."""
    nodes = _load_nodes(brain_path)
    emb = embedder or get_embedder()
    texts = [search_haystack(n) for n in nodes]
    index = {
        "version": 2,
        "embedder": {"id": emb.id, "dim": emb.dim},
        "node_ids": [n["id"] for n in nodes],
        "node_text_sha256": [search_fingerprint(n) for n in nodes],
        "vectors": emb.embed(texts) if texts else [],
    }
    if not valid_index(index):
        raise ValueError("Embedding provider returned an invalid vector collection")
    return index


def write_index(index: dict, out_path: str = BRAIN_VEC) -> None:
    """Activate a complete private index; failure preserves the previous artifact."""
    if not valid_index(index):
        raise ValueError("Invalid embedding index")
    payload = json.dumps(index, sort_keys=True, separators=(",", ":"), allow_nan=False)
    destination = os.path.abspath(out_path)
    if os.path.lexists(destination) and (os.path.islink(destination) or not os.path.isfile(destination)):
        raise ValueError("Embedding destination must be a regular file")
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".brain-projection-", suffix=".db", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if os.path.islink(destination):
            raise ValueError("Embedding destination changed to a symlink")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def load_index(path: str = BRAIN_VEC) -> dict | None:
    """Unsupported, malformed or missing indexes select the lexical fallback."""
    try:
        index = _read_json(path)
        return index if valid_index(index) else None
    except (OSError, ValueError, OverflowError):
        return None


def main() -> int:
    if not settings.features.semantic_search:
        # Master switch off -> clean no-op; the brain stays lexical-only.
        print("semantic_search off — skipping embedding index.", flush=True)
        return 0
    emb = get_embedder()
    index = build_index(BRAIN_JSON, emb)
    write_index(index)
    print(f"Wrote {BRAIN_VEC} ({len(index['node_ids'])} node vector(s), "
          f"embedder={index['embedder']['id']}, dim={index['embedder']['dim']}).",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
