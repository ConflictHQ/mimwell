# Curation

A mind palace is only useful if what is in it is right. Mimwell's rule is
simple: **anyone, person or agent, can suggest; only a reviewer can accept;
and accepted knowledge keeps its history.** This page covers the tools that
enforce that rule.

## Suggestions and the review queue

Suggested connections live in `app/proposals.json` (format `proposals/v1`).
Each one is an unaccepted claim, for example that two names mean the same
thing, together with its evidence. The portal's **Proposals** page shows the
queue read-only, so curators can see what is waiting.

A suggestion's confidence score or producer never promotes it. Acceptance is a
deliberate edit by a curator to `app/equivalences.json`:

```json title="app/equivalences.json"
{
  "equivalences": [
    {
      "source": "wiki:knowledge/wiki/release-process",
      "target": "doc:knowledge/docs/guides/onboarding",
      "rel": "aligns_with",
      "confidence": 0.8,
      "asserted_by": "sam",
      "evidence": "Both describe the release checklist",
      "date": "2026-09-26"
    }
  ],
  "dismissed": []
}
```

`rel` is `same_as`, `facet_of` or `aligns_with`. `make build` turns each entry
into a graph edge that carries who asserted it, the confidence and the
evidence. Rejected suggestion ids go in `dismissed`, so a rejection is
remembered. Because this is a file in version control, every acceptance is a
reviewable change, and a wrong one is removed by deleting its entry.

## Curation rules for the concept graph

`app/knowledge_graph.json` holds a free-form concept graph, often produced by
an extraction tool or an agent. Such graphs are noisy: the same thing under two
names, wrong types, filler entries. Curation rules fix that without editing the
extractor.

```json title="knowledge/curation.json"
{
  "merges":   { "PostgreSQL": ["Postgres"] },
  "typeFixes": { "Orders service": "service" },
  "drops":    ["TODO"]
}
```

```bash
python3 scripts/curate-kg.py
```

Given a graph with `Postgres`, `PostgreSQL`, `Orders service` and `TODO`, this
merges the two database names into `PostgreSQL` (keeping both descriptions),
retypes `Orders service` as a `service`, drops `TODO`, and removes the edge
that became a duplicate. `--in`, `--out` and `--rules` override the default
paths. Rules are data, so rerunning after each extraction gives the same
result.

## Decision lineage

Decisions change. Decision lineage records each change as an immutable
**revision**, so you can see what was decided, when it took effect, who had the
authority, why it changed and what it replaced.

Enable the `decision-lineage` overlay:

```json title="client.config.json (excerpt)"
{ "profile": { "base": "core", "overlays": ["engagement", "data", "decision-lineage"] } }
```

Revisions live in `app/decision-lineage.json`. A later revision names the
aspects it changes (as JSON pointers such as `/hosting`), the relation
(`amends`, `supersedes` or `reverses`), and the SHA-256 digest of the revision
it changes:

```json title="app/decision-lineage.json (abridged)"
{
  "protocolVersion": "1.0",
  "decisions": [
    {
      "id": "db-choice.1",
      "decision": "db-choice",
      "title": "Use PostgreSQL for orders",
      "values": { "/engine": "postgresql", "/hosting": "managed" },
      "review": { "state": "accepted", "by": "sam", "at": "2026-01-10T11:00:00Z",
                  "reason": "Team agreed in review" },
      "changes": []
    },
    {
      "id": "db-choice.2",
      "decision": "db-choice",
      "title": "Self-host PostgreSQL",
      "values": { "/hosting": "self-hosted" },
      "review": { "state": "accepted", "by": "sam", "at": "2026-03-02T08:30:00Z",
                  "reason": "Cost review approved" },
      "changes": [
        { "target": "db-choice.1", "relation": "amends", "fields": ["/hosting"],
          "sha256": "<digest of db-choice.1>" }
      ]
    }
  ]
}
```

Each revision also carries `subject`, `scope`, `recordedAt`, `effectiveFrom`,
`author`, `authority`, `reason`, `withdraws`, `evidence` and `legacyDecision`;
`schemas/decision-lineage.schema.json` is the full contract. The digest is the
SHA-256 of the target revision's canonical JSON (sorted keys, no whitespace),
which `decision_lineage.digest()` computes:

```bash
PYTHONPATH=scripts python3 -c "
import json, decision_lineage as d
rows = json.load(open('app/decision-lineage.json'))['decisions']
print(d.digest(rows[0]))
"
```

`make build` compiles both revisions into `DecisionRevision` nodes, linked by
a `decision.amends` edge. The rules are strict, and each violation fails the
build:

- A revision that changes another must pin its exact digest. Editing an
  accepted revision after the fact breaks the pin.
- An accepted change needs an accepted predecessor.
- A change cannot come before the revision it changes, and it cannot touch
  aspects that do not exist in both.

## The record authority

For teams that want reviewed writes in a database rather than in files,
Mimwell includes a record authority: `scripts/knowledge-store.py`, with verbs
for the whole curation cycle.

| Verbs | Purpose |
|---|---|
| `init`, `describe`, `inspect` | create and examine an adopted store |
| `get`, `search`, `context`, `path`, `nearest` | read |
| `propose`, `review`, `dispose`, `commit` | suggest, review, accept or reject, and write |
| `export`, `restore`, `migrate`, `cutover`, `resume` | move and upgrade stores |
| `project`, `reindex`, `deliver` | rebuild projections from the authority |

Adopting an authority means declaring a contract (the stores, including the
[blob store](storage.md#blob-stores)) and a knowledge policy (who may read and
write which kinds). Actor identities come from the host, never from a request
or a model.

!!! warning "Advanced, and not yet packaged for this release"
    The record authority is present, but its worked example depends on
    example contract and policy files that this release does not ship yet.
    Until they do, file-based curation above is the supported path.
