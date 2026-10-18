# Native records, apps and local ingestion

Check `edition.json` for the exact files and source revision in your edition.
Installing engine code does not adopt a record authority, enroll an app, grant a
principal access, or migrate an existing brain. Keep the selected native contract,
identity map and private host configuration under operator control.

## Storage routes

A native contract selects one record/journal authority and at most one blob-role
store. Deployment configuration maps the declared store IDs to environment or
secret references. Record metadata, immutable binary bytes, external source
folders, projections and backups keep their declared owners and destinations.
An absent or ambiguous route must fail; another configured connection is not a
fallback writer.

One filesystem blob store can use multiple relative subfolders. Multiple selected
document folders retain path-based identity. Separate host-registered database
aliases remain independent authorities: a request selects one alias and does not
fan out, shard a canonical brain or form a transaction across databases. Changing
a deployment connection never performs an implicit migration.

## Local connector exports

The local export adapters normalize selected source bytes into
`connector-event/v1` JSONL:

| Entry point | Selected export formats |
| --- | --- |
| `scripts/platform-export.py` | Slack, Teams, Zoom and Discord profiles; `--capabilities` reports exact support |
| `scripts/messaging-export-adapter.py` | Profiled WhatsApp text, Telegram Desktop JSON and an operator-produced Signal bridge |
| `scripts/social-export.py` | Supported social export profiles and explicit inert mappings; inspect `--capabilities` |

These adapters read offline exports. They do not log in to a platform, poll an API,
fetch attachment URLs or register a native writer. Ambiguous formats and missing
required timestamps, timezone choices or mappings are refused.

The operator independently registers the exact export path, namespace and digest
with the local connector host. `scripts/connector-host.py` checks current identity,
policy and that registration before admitting events as pending native proposals.
Independent review and native commit remain separate. A delete or access-change
event does not recall previously copied data or silently change local access.
Python, Go and Rust clients are described in [the connector guide](../connectors/README.md).

## Authoring and writeback

Native edits use proposal, independent review and commit against the selected
authority and expected revision. Learned changes use the same review path; model
output does not become an approval or a canonical record by itself.

The optional local Git writer supports explicitly registered JSON, Markdown and
bounded binary paths through review branches and pinned publication destinations.
It does not write collections owned by an adopted structured authority. Source
folder selection is not write permission. Delivery receipts and reconciliation
must establish the outcome of a lost response before another publication attempt.

## App descriptions and runtime installation

The opt-in `apps` ontology overlay extends `data` with App, Component and App Query
records. Definitions pin dependency revisions and contain no datasource
credentials or executable query transport. Reads report missing, changed or
unreadable dependencies as unavailable.

App attachments bind exact immutable locators, sizes, digests and media types.
PGlite snapshot metadata also pins runtime versions, gzip compression, expanded
size and digest, with SQL or CSV fallback. Byte verification is required before a
consumer opens data. These descriptions do not install or execute an app.

An installed static app follows owner review of `apps/<id>/`, its manifest and the
adopted app collection contract, followed by explicit private host enrollment and
per-user credentials. Drafts stay disabled with empty grants. The host supplies
the runtime bridge and intersects user permissions with the app's grant. Removing
a manifest disables serving; retained data still follows native export and
retention policy.

Per-bundle and per-App byte limits are not a total brain storage quota. A protected
transfer envelope does not establish destination encryption at rest. Protected
attachment destinations remain unavailable without a qualified durable byte
protection adapter. This edition does not supply an automatic installer, a
brain-wide retained-byte admission service or a browser PGlite restore guarantee.

## Maintenance

`scripts/store-maintenance.py` exposes host-authorized inspection, bounded cache
maintenance, migration reporting and isolated snapshot capture/restore.
`scripts/inspect-maintenance.py` reports semantic findings through a pinned context
host. Logical memory compaction remains a reviewed native change; physical cache
compression does not rewrite canonical meaning. A snapshot is complete only when
its referenced blob bytes and selected protection requirements are also preserved.
