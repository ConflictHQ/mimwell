# Context API for agents

The portal serves people. The context API serves software: coding agents, AI
apps and scripts that need grounded context from your brain. It is the
"context store" part of Mimwell.

It is a small, read-only HTTP service. Each call is authenticated, filtered
through a read policy before anything is returned, bounded by explicit budgets,
and pinned to an exact revision of the brain, so two calls with the same basis
see the same data.

| Route | Returns |
|---|---|
| `POST /basis` | the current revision pins: brain, ontology, policy, bindings, recipe |
| `POST /search` | ranked matches for a keyword query |
| `POST /context` | a bounded bundle of nodes and edges around a subject, grouped by your recipe |
| `POST /documents` | document matches from an optional corpus index (not covered here) |

There are no write routes.

## Setting it up

The service reads four operator-owned files. Keep them under `_internal/`,
which the portal never serves.

### 1. A read policy

The policy names who may read, in which scope, and which kinds of records
count as readable resources.

```json title="_internal/context/policy.json (abridged)"
{
  "protocolVersion": "1.0",
  "id": "example-policy",
  "version": "1.0.0",
  "principals": [{ "id": "coding-agent", "kind": "agent" }],
  "scopes": [
    {
      "id": "shared", "parent": null, "space": "product", "owner": "coding-agent",
      "practice": { "id": "read", "version": "1.0.0",
                    "path": "_internal/context/practice.md", "sha256": "<file sha256>" },
      "rules": { "readers": ["coding-agent"], "proposers": ["coding-agent"],
                 "committers": [], "reviewers": [], "fastAuto": false,
                 "separateReview": true, "allowDelete": false, "retentionDays": 0 }
    }
  ],
  "exceptions": [],
  "resources": [
    { "id": "shared.doc", "scope": "shared", "kind": "doc", "retentionSince": null },
    { "id": "shared.source", "scope": "shared", "kind": "source", "retentionSince": null }
  ]
}
```

- A root scope must declare every rule, even the empty ones.
- Versions are `major.minor.patch`.
- Resource `kind` values are the ontology's kind ids (`doc`, `source`,
  `memory-note` and so on), not the node names you see in the graph.
- The practice file is a short Markdown note describing how this scope is
  used; the policy pins its hash.

### 2. Bindings

Bindings map every record to a policy resource. **Anything unbound is not
returned.** Each node, each edge and each source path on a record must be
bound; if one path on a record is unbound, the whole record is withheld. This
script binds everything in `app/brain.json` to the `shared` scope:

```python
import json, sys
sys.path.insert(0, "scripts")
from context_access import edge_identity, record_paths

brain = json.load(open("app/brain.json"))
kind_of = {k["node"]: k["id"] for k in json.load(open("brain-schema.json"))["kinds"]
           if isinstance(k.get("node"), str)}
resource = {n["id"]: "shared." + kind_of[n["kind"]] for n in brain["nodes"]}
bindings = {
    "nodes": resource,
    "edges": {edge_identity(e): resource[e["source"]] for e in brain["edges"]},
    "paths": {p: resource[n["id"]] for n in brain["nodes"] for p in record_paths(n)},
    "assertions": {},
    "references": {},
}
json.dump(bindings, open("_internal/context/bindings.json", "w"), indent=1)
```

For real access control, bind sensitive kinds or paths to resources in a
scope only some principals can read. Rerun this after each build, since edge
identities change when edges do.

### 3. A recipe

A recipe says which relationships to follow from the subject, and names the
group each hop fills.

```json title="_internal/context/recipe.json"
{
  "id": "schema-walk",
  "version": "1.0.0",
  "hops": [
    { "rel": "has_entity", "direction": "out", "transitive": false, "as": "tables" }
  ]
}
```

Each hop starts from the subject. `transitive: true` keeps following the same
relationship outward, up to the request's `maxHops`.

### 4. The host file

The host file pins the other three, plus the compiled graph, by SHA-256. If
any pinned file changes, requests are refused until the host file is updated.

```json title="_internal/context/host.json"
{
  "protocolVersion": "1.0",
  "graph":    { "path": "app/brain.json", "sha256": "<file sha256>",
                "asOf": "2026-09-26T00:00:00Z" },
  "policy":   { "path": "_internal/context/policy.json", "sha256": "<file sha256>",
                "ontologySha256": "<sha256 of brain-schema.json>" },
  "recipe":   { "path": "_internal/context/recipe.json", "sha256": "<file sha256>" },
  "bindings": { "path": "_internal/context/bindings.json", "sha256": "<file sha256>" },
  "scopes":   ["shared"],
  "collection": null
}
```

## Running the service

`scripts/context_http.py` provides a standard WSGI application. Credentials are
bearer tokens, stored only as SHA-256 digests. A minimal local server:

```python title="serve_context.py"
import hashlib, sys
sys.path.insert(0, "scripts")
from wsgiref.simple_server import make_server
from context_http import ContextApplication, ContextEndpoint

TOKEN = "example-agent-token-change-me"
credentials = lambda: [{"sha256": hashlib.sha256(TOKEN.encode()).hexdigest(),
                        "actor": "coding-agent", "expiresAt": None}]
endpoint = ContextEndpoint(root=".", host_config="_internal/context/host.json",
                           credentials=credentials)
make_server("127.0.0.1", 8765, ContextApplication(endpoint)).serve_forever()
```

The credential function is called on every request, so returning a new list
revokes a token immediately. Use long random tokens, never passwords. For
anything beyond your own machine, run the application behind TLS in a real
WSGI server; `runtime/context-service/gunicorn.conf.py` is a hardened starting
configuration.

## Calling it

Every call is a `POST` with `Content-Type: application/json` and
`Authorization: Bearer <token>`. A missing or wrong token gets `401`, and
failures return an empty body with a status code, never error details.

**1. Get the basis.**

```bash
curl -s -X POST http://127.0.0.1:8765/basis \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
```

The response carries `scopes`, `recipe`, `asOf` and `revisions`. Send them back
unchanged on the next calls; a request with a stale revision is refused with
`400`, so an agent never mixes two versions of the brain.

**2. Search.**

```json title="search request"
{
  "protocolVersion": "1.0",
  "query": "orders customer",
  "scopes": ["shared"], "recipe": { "...": "from /basis" },
  "asOf": "2026-09-26T00:00:00Z", "revisions": { "...": "from /basis" },
  "budget": { "maxMatches": 5, "maxBytes": 20000 }
}
```

Matches come back ranked by a deterministic keyword score, with the matched
terms and the full record for each hit.

**3. Get context around a subject.**

```json title="context request"
{
  "protocolVersion": "1.0",
  "target": { "type": "subject", "id": "source:shop",
              "question": "What tables does the shop database have?" },
  "scopes": ["shared"], "recipe": { "...": "from /basis" },
  "asOf": "2026-09-26T00:00:00Z", "revisions": { "...": "from /basis" },
  "budget": { "maxNodes": 20, "maxEdges": 20, "maxHops": 2,
              "maxReferences": 0, "maxQuestions": 0, "maxBytes": 50000 }
}
```

With the schema-walk recipe and the example database from
[Data sources](sources.md#system-inventory), the response's `groups` holds
`{"tables": ["source:shop:entity:customers", "source:shop:entity:orders"]}`,
with the matching `nodes` and `edges`. The response also reports `gaps`, for
example records with no attached evidence, and `truncation` when a budget cut
the result short, so an agent knows what it did not get.

## What agents can rely on

- **Only what the policy allows.** Records outside the actor's readable
  resources never appear, and responses do not reveal that they exist.
- **Stable answers.** Pinned revisions and deterministic ordering mean the same
  request returns the same bytes until the brain changes.
- **Bounded cost.** Every request states its budget, and the server enforces
  its own ceilings on top.
- **No hidden writes.** The service cannot change the brain. Changes go through
  [curation](curation.md).
