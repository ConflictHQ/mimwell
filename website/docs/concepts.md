# Concepts

## The brain

A brain is a Git repository with three layers:

1. **Sources.** What you write: Markdown documents under `knowledge/docs/`,
   structured records under `app/` (decisions, action items, glossary terms,
   stakeholders and more), and `client.config.json`. Adapters can add wiki
   pages, issue and activity snapshots and database schemas; see
   [Data sources](data/sources.md).
2. **Generated artifacts.** What `make build` writes from the sources: the
   brain graph (`app/brain.json`), the search pack (`app/knowledge-pack.json`),
   the document manifest and the brain manifest.
3. **The portal.** Static pages plus a Cloudflare Worker (`worker.js`) that
   serve the generated artifacts, run search and host the chat agent.

Everything lives in files. There's no database to run: the build output is
what the portal serves. Optional stores are covered in [Storage](data/storage.md).

## Knowledge versus generated artifacts

Sources are the truth. Generated artifacts are projections of them, rebuilt on
every `make build`, so never edit them by hand. Change the source and rebuild.

The build is deterministic: the same sources produce the same artifacts, byte
for byte. That makes changes easy to review in a pull request.

## Documents and records

**Documents** are prose: Markdown files under `knowledge/docs/`. They feed the
search pack and the library, so readers and the agent can find and read them.

**Records** are structured entries in the `app/*.json` files, each checked
against a JSON Schema in `schemas/`. They become nodes in the brain graph. For
example, a decision in `app/decisions.json`:

```json
{
  "title": "Keep team knowledge in one brain",
  "decision": "We compile our documents and records into a single Mimwell brain.",
  "date": "2026-09-26",
  "owner": "Handbook team"
}
```

The record kinds a brain uses come from its **profile**: a base (`core`) plus
overlays such as `engagement`, `data` or `sensemaking`. Profiles live in
`profiles/`, and `client.config.json` picks them under `profile`.

## The graph

`app/brain.json` holds every record as a node, with typed edges between them.
The portal's pages, the graph views and the agent's graph search all read from
it. The generated `app/kinds.json` lists each record kind the brain supports.

## Search

The search pack (`app/knowledge-pack.json`) indexes your documents and records.
The portal's search box and the chat agent both use it. An optional semantic
index adds meaning-based matches for Python tooling; see
[Storage](data/storage.md#vectors-and-semantic-search).

## The portal

The portal is the reader's way into the brain. Its home page adapts to the
brain's purpose, set by `portal.template` in `client.config.json`: for example
`engagement`, `company`, `topic`, `personal` or `wiki`.

### Easy and Advanced views

The **Easy view** is the default home: a simple entry point for readers who
want answers, not structure. The **Advanced view** shows every record kind,
the graph and the sources. Readers can switch between them, and the portal
remembers their choice. Set the default with `portal.view.default`.

## The agent

The chat agent answers from the brain's own content and cites what it used.
It runs inside the Worker and needs an `ANTHROPIC_API_KEY` secret. Its model,
turn limit and voice are set under `assistant` in `client.config.json`.

For agents outside the portal, such as coding agents and AI apps, the
[Context API](data/context-api.md) serves the same brain over authenticated,
policy-filtered HTTP.

## Curation

Anyone, person or agent, can suggest a change; only a reviewer accepts it, and
accepted decisions keep their history. See [Curation](data/curation.md).

## Access

A brain can be public, or served behind Cloudflare Access. With Access in
front, the optional `access` block restricts paths to named owners. The rules
apply to every page, search result and agent answer, and a block the engine
can't parse locks everything down rather than opening it. See
[Configuration](configuration.md#access).
