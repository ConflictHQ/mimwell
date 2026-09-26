# Storage

A brain keeps three kinds of stored data, and each has its own targets:

- **The compiled graph:** the projection `make build` produces, which the
  portal, search and the agent read.
- **Vectors:** an optional semantic index over the compiled graph.
- **Blobs:** original files and evidence attached to records in an adopted
  record authority (see [Curation](curation.md#the-record-authority)).

None of these is where your knowledge lives. Your sources are the truth; stores
are rebuilt from them.

## The compiled graph

`brain.store` in `client.config.json` selects the backend that tools read the
graph through. Every backend answers the same queries (`get_node`, `search`,
`neighbors`, `path`, `subgraph`) with the same results in the same order.

| `brain.store` | Where it lives | Status in this release |
|---|---|---|
| `json` (default) | `app/brain.json`, loaded into memory | Works out of the box |
| `sqlite` | `app/brain.db`, queried with recursive SQL | Reader only; this release does not ship the step that writes `app/brain.db` |
| `d1` | Cloudflare D1, queried by the Worker at the edge | Reader only; also needs `features.brain_d1`, a D1 binding and your Cloudflare account; this release does not ship the push step |

Use `json` today. It suits small and medium brains, and the Worker serves it
with no extra setup. From Python, the same accessor is available to your own
tooling:

```bash
PYTHONPATH=scripts python3 -c "
import brain_store as b
print([n['id'] for n in b.search('orders')])
print([n['id'] for n in b.neighbors('source:shop', 'out')])
"
```

## Vectors and semantic search

Plain search matches substrings. Semantic search also finds nodes that are
about your question without sharing its words. It is opt-in:

```json title="client.config.json (excerpt)"
{ "features": { "semantic_search": true } }
```

Then build the index from the compiled graph:

```bash
python3 scripts/embed-brain.py
```

This writes `app/brain.vec.json`, a derived cache you should not commit. The
default embedder, `local-charngram-hash@1`, runs locally with no model
download and no API key. `hybrid_search` combines three signals: the lexical
match, vector similarity, and one hop of graph neighbours around the best hits.

```bash
PYTHONPATH=scripts python3 -c "
import brain_store as b
print([n['id'] for n in b.hybrid_search('customer email')])
"
```

If the feature is off, or the index is missing or malformed, `hybrid_search`
falls back to exactly the plain search result. Each index read checks the
embedder and every record's current text, so a record edited since the last
`embed-brain.py` run never scores on its old vector. Rebuild the index after
each build.

To use a hosted embedding model instead, name a provider module and class in
`semantic.embedder`. The provider exposes `embed(list[str]) -> list[vector]`,
and reads its own key from the environment variable you name in `apiKeyEnv`;
Mimwell never reads the key itself.

```json
{
  "semantic": {
    "embedder": {
      "module": "my_embeddings",
      "class": "Embedder",
      "model": "your-model-id",
      "apiKeyEnv": "MY_EMBEDDINGS_KEY",
      "dim": 1024
    }
  }
}
```

!!! note
    Semantic search runs in Python tooling. The deployed Worker's search and
    chat agent use the compiled graph and search pack, not the vector index.

## Blob stores

Blobs are the bytes behind a record: an original document, a recording, a
piece of evidence. A record points at a blob with a locator
(`store`, `key`, `sha256`, `bytes`, `mediaType`), and every read checks the
bytes against that digest. Keys are write-once: writing different content to
an existing key is refused.

| Driver | Where the bytes live | What you need |
|---|---|---|
| `fs` | a folder on disk or a mounted volume | nothing extra |
| `db-blob` | a table in the record authority's database, up to 16 MiB per blob | nothing extra |
| `s3` | S3, R2, MinIO, Garage, or GCS through its S3 interface | `pip install boto3`, plus your bucket and credentials |
| `azure-blob` | Azure Blob Storage | `pip install azure-storage-blob`, plus your account and credentials |

An `s3` store's location is `s3://<bucket>/<prefix>`, and an `azure-blob`
store's is `azure-blob://<container>/<prefix>`; the SDK reads credentials the
usual way for that cloud (environment variables, profile or managed
identity). The cloud SDKs load only when a store of that driver opens. The
`s3` and `azure-blob` drivers need your own cloud account; they were not
exercised against a live bucket for these docs. Blob stores belong
to an adopted record authority and are declared in its contract; see
[Curation](curation.md#the-record-authority).
