# Native records, apps and local ingestion

Check `edition.json` for the exact files and source revision in this edition. Installing engine code does not adopt a record authority, enroll an app, grant a principal access, or migrate an existing brain. Keep the selected native contract, identity map and private host configuration under operator control.

## Storage routes

A native contract selects one record/journal authority and at most one blob-role store. Deployment configuration maps declared store IDs to environment or secret references. Record metadata, immutable binary bytes, external source folders, projections and backups keep their declared owners and destinations. An absent or ambiguous route must fail; another configured connection is not a fallback writer.

One filesystem blob store can use multiple relative subfolders. Multiple selected document folders retain path-based identity. Separate host-registered database aliases remain independent authorities: a request selects one alias and does not fan out, shard a canonical brain or form a transaction across databases. Changing a deployment connection never performs an implicit migration.

## Local connector exports

The local export adapters normalize selected source bytes into `connector-event/v1` JSONL:

| Entry point | Selected export formats |
| --- | --- |
| `scripts/platform-export.py` | Slack, Teams, Zoom and Discord profiles; `--capabilities` reports exact support |
| `scripts/messaging-export-adapter.py` | Profiled WhatsApp text, Telegram Desktop JSON and an operator-produced Signal bridge |
| `scripts/social-export.py` | Supported social export profiles and explicit inert mappings; inspect `--capabilities` |

These adapters read offline exports. They do not log in to a platform, poll an API, fetch attachment URLs or register a native writer. Ambiguous formats and missing required timestamps, timezone choices or mappings are refused.

The operator independently registers the exact export path, namespace and digest with the local connector host. `scripts/connector-host.py` checks current identity, policy and that registration before admitting events as pending native proposals. Independent review and native commit remain separate. A delete or access-change event does not recall previously copied data or silently change local access. Python, Go and Rust clients are described in [the connector guide](../connectors/README.md).

## Authoring and writeback

Native edits use proposal, independent review and commit against the selected authority and expected revision. Learned changes use the same review path; model output does not become approval or a canonical record by itself.

The optional local Git writer supports explicitly registered JSON, Markdown and bounded binary paths through review branches and pinned publication destinations. It does not write collections owned by an adopted structured authority. Source-folder selection is not write permission. Delivery receipts and reconciliation establish the outcome of a lost response before another publication attempt.

## App descriptions and owner installation

The opt-in `apps` ontology overlay extends `data` with App, Component and App Query records. Definitions pin dependency revisions and contain no datasource credentials or executable query transport. Reads report missing, changed or unreadable dependencies as unavailable.

App attachments bind exact immutable locators, sizes, digests and media types. PGlite snapshot metadata also pins runtime versions, gzip compression, expanded size and digest, with SQL or CSV fallback. Byte verification is required before a consumer opens data. These descriptions do not install or execute an app.

The selected local owner operation can preview and apply an exact reviewed App bundle to an adopted local SQLite brain. It is bound to the reviewed source commit and bundle digest and leaves the installed App disabled as a draft. It does not enroll the App, activate serving, grant user access, or expose install methods through Studio Apps JSON-RPC or bearer tokens. Separate owner-controlled enrollment and credentials remain required before serving.

Per-bundle and per-App byte limits are not a total brain quota. The opt-in admission service covers selected local writer routes and reports bounded logical inventory; `aggregateCapacity.available` remains false. This is not a physical disk, filesystem, WAL or memory limit.

Protected attachment chunks and stored bytes are supported only through the selected per-record provider route after current host and policy checks. The provider seals bytes before durable storage and binds the envelope to attachment context. This does not protect native record bodies, history or metadata. Unsupported profiles and routes refuse instead of falling back to plaintext.

## Protected snapshot capture and maintenance

A trusted maintenance host can supply the selected protection adapter for bounded capture on the supported retained-content route, with opaque metadata disabled and offline retain authorized. The ordinary command-line interface has no adapter and refuses adopted capture. Opening the read-only SQLite authority may create coordination sidecars, so capture does not promise zero filesystem effects. Protected restore, activation and cutover remain unavailable; capture does not qualify aggregate capacity.

`scripts/store-maintenance.py` also exposes host-authorized inspection, bounded cache maintenance and migration reporting. `scripts/inspect-maintenance.py` reports semantic findings through a pinned context host. Logical memory compaction remains a reviewed native change; physical cache compression does not rewrite canonical meaning. A snapshot is complete only when its referenced blob bytes and selected protection requirements are also preserved.

## Selected collection navigation and reviewed identifier tools

The optional SQLite collection browser uses the explicit v11 operations host
and v13 request/result route; no shipped host opts in. Current viewer, owner,
credential and native revision checks still govern every page and editor
selection. It exposes no hidden counts or new write permission. See the fresh
public [native collection guide](native-collection-browser.md).

Reviewed identifier migration is an operator-only preview/plan/apply/recovery
workflow for selected current plain JSON. It preserves all bytes outside the
explicit root marker change and refuses unsupported files, metadata and writer
conditions. It does not migrate native authority state, signed history or frozen
catalogs, and does not retire compatibility readers. See the fresh public
[identifier migration guide](identifier-migration.md).
