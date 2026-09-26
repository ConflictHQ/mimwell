# Data sources

A brain is compiled from sources. `make build` reads every configured source,
normalizes it into graph nodes and edges, and writes `app/brain.json`. Sources
never get edited by the build; they stay the originals you change.

Mimwell reads five families of sources:

| Family | What it reads | Enabled by |
|---|---|---|
| Documents | Markdown under `knowledge/docs/` | on by default |
| Memory | Markdown facts under `knowledge/memory/` | on by default |
| Structured records | JSON registers under `app/` and `specs/` | on by default |
| Source adapters | Wiki pages, doc projections, issue and activity snapshots | `brain.sourceAdapters` plus an ontology overlay |
| System inventory | Database schemas and other systems of record | `generators.sources` (on by default) |

## Documents and memory

Every Markdown file under the folders in `knowledge.sources` becomes part of
the library and the search pack, so readers and the agent can find it. The
default is `knowledge/docs`, read recursively.

Files under `knowledge/memory/` become `Memory` nodes in the graph: short,
durable facts the team always wants true. One file is one node, with an id
taken from its path.

```markdown title="knowledge/memory/deploy-freeze.md"
---
title: Deploy freeze on Fridays
---

We do not deploy on Fridays.
```

After `make build`, the graph holds `memory:knowledge/memory/deploy-freeze`.

Two keys in `knowledge` control what is read:

- `skipNames`: file names to ignore everywhere (the default skips `README.md`
  and agent instruction files).
- `excludeFromBrain`: repo-relative globs to keep out of the graph.

## Structured records

Registers are JSON files you fill in, one per record kind. Each has a schema
under `schemas/`, and `make verify` validates them.

| File | Becomes |
|---|---|
| `app/decisions.json` | decisions |
| `app/open-questions.json` | open questions |
| `app/action-items.json` | action items |
| `app/sessions.json` | meetings and working sessions |
| `app/raid.json` | risks, assumptions, issues, dependencies |
| `app/roadmap.json` | roadmap items |
| `app/deliverables.json` | deliverables |
| `app/user-stories.json` | user stories |
| `app/people.json`, `app/stakeholders.json`, `app/organizations.json` | people and organizations |
| `app/glossary.json` | terms |
| `app/equivalences.json` | accepted "same thing" links |
| `app/dependencies.json` | dependencies |
| `app/knowledge_graph.json` | a free-form concept graph (see [Curation](curation.md)) |
| `specs/` | plan documents with frontmatter |

Which kinds exist in your brain comes from the ontology profile in
`client.config.json` (`profile.base` and `profile.overlays`). See
[Configuration](../configuration.md#profile).

## Source adapters

Source adapters project extra inputs into typed graph nodes. Each one needs
its ontology overlay, so the kind it produces is declared, and an explicit
entry in `brain.sourceAdapters`.

| Adapter | Reads | Node kind | Overlay |
|---|---|---|---|
| `docs` | Markdown under the `docs` source folders | `Doc` | `documents` |
| `wiki` | Markdown under `knowledge/wiki/` | `WikiPage` | `documents` |
| `issues` | `issues.json`, a snapshot of tracker issues | `Issue` | `tracker` |
| `activity` | `activity-snapshot.json`, a snapshot of commits or events | `ActivityEvent` | `activity` |

For example, to turn docs and wiki pages into graph nodes:

```json title="client.config.json (excerpt)"
{
  "profile": { "base": "core", "overlays": ["engagement", "data", "documents"] },
  "brain": { "sourceAdapters": ["docs", "wiki"] }
}
```

```markdown title="knowledge/wiki/release-process.md"
---
title: Release process
---

How we ship a release.
```

`make build` then emits `wiki:knowledge/wiki/release-process` (a `WikiPage`)
and one `Doc` node per document. Adapters never fetch anything: the issue and
activity adapters read snapshot files you produce with your own tooling, and a
selected snapshot that is missing or malformed fails the build instead of
silently producing nothing.

## System inventory

The inventory records the systems your knowledge is about: databases, APIs,
catalogs. It uses one shape for every technology:

```text
source   (a database, an API, a catalog)
  entity (a table, resource or type)
    field (a column, property or attribute)
```

Each level can carry `status`, `owner` and `provenance`, so the inventory shows
what exists, where it came from and how far a review has got.

Extractors are registered by name. The shipped, working extractor is
`sql-ddl`, which reads `CREATE TABLE` statements. `api-schema`,
`json-schema`, `csv-headers` and `catalog` are registered interfaces that
return nothing until you implement them; adding one is a single decorated
function in `scripts/ingest_sources.py`.

Put DDL files in `sources/ddl/`:

```sql title="sources/ddl/shop.sql"
CREATE TABLE customers (
  id INTEGER PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  created_at TIMESTAMP
);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  status VARCHAR(32),
  total NUMERIC(10,2)
);
```

`make build` (or `python3 scripts/ingest_sources.py` on its own) writes
`app/sources.json` with one source (`shop`), two entities and seven fields.
The graph gains `Source`, `Entity` and `Field` nodes, for example
`source:shop:entity:orders`, which search and the agent can then find.

To read inputs from another folder, or to turn the inventory off:

```json
{ "generators": { "sources": { "input_dir": "schemas-dump" } } }
```

```json
{ "generators": { "sources": false } }
```

The output is sorted by id and name, so reruns produce identical files.
