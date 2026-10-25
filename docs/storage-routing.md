# Storage routing

Storage contracts name the record/journal authority, any blob store, source folders, projections, and backup destinations. The caller selects the declared route; a folder name, familiar connection, or available credential never chooses a route, and a failed route does not fall back to another store.

## Record and blob routes

A host contract selects one record/journal authority for each request. A SQLite authority may keep native record and journal data in its database. If that contract declares a database blob role, blob bytes may be inline in that database; alternatively, an explicitly declared filesystem blob store may hold them under its selected store ID. These are distinct declared route shapes, not interchangeable fallback destinations. A locator binds bytes to a store ID, relative key, digest, size, and media type.

Source folders are separate inputs. A host may register multiple folders explicitly; adapters preserve their path identity and do not write back to the source folders. Separate native authority aliases remain independent: each request selects one registered authority, and writes do not fan out or form a cross-database transaction.

Native projections use another route. An authenticated host registration selects a private projection destination and principal. The client previews the projection, pins its digest, and asks the host to deliver it; the native writer rechecks the selected registration and sink before acknowledging delivery. A projection destination is not a `brain.stores[]` blob role.

The routing matrix describes supported resource shapes. It does not identify a private deployment's configuration or qualify its credentials, host policy, operations, or public acceptance.

## Hosted resource bindings

Hosts consume the edition's pinned `substrate-cells.json` at its existing root location. Its `schemaVersion: 1` document contains all four axes and all 192 cells, each with a `supported`, `planned`, or `unsupported` status and a reason. Read this artifact instead of porting the engine's cell-selection code. A supported cell describes an adapter combination; provisioning, authority adoption, permissions, and live service qualification remain separate operations.

The selected native contract identifies stores and roles. In `client.config.json`, each `brain.stores[].dsn` references a host-supplied environment variable or secret bundle. Store IDs must be unambiguous. The local knowledge-store CLI resolves environment DSN references only; secret-bundle references require a supported host resolver. Connection values and credentials stay outside generated manifests and route receipts.

| Persistence | Host binding |
| --- | --- |
| Native local SQLite | Set `BRAIN_ROOT=/srv/brain`; mount private state at `/srv/brain/_internal` and use one replica. The authority's selected DSN variable contains a relative path such as `_internal/canon.sqlite`. Match the image UID and native private-state permissions. |
| Compiled SQLite graph | The legacy `/data` volume holds a rebuildable graph projection. It is separate from the native record authority. |
| PostgreSQL | The managed service supplies `DATABASE_URL`. A declared PostgreSQL authority can select `{"id":"canon","dsn":{"env":"DATABASE_URL"}}`. Provision the service and adapter before explicit native initialization or cutover. |
| EFS | Mount the shared filesystem at `/shared`. An explicitly selected filesystem blob DSN can name `/shared/media`; shared files do not make SQLite multi-writer. |
| S3 | Supply the selected location variable, for example `BRAIN_BLOBS_DSN=s3://<bucket>/<prefix>`, and `AWS_DEFAULT_REGION=<region>`. These contain a location and region, not access credentials. Existing secret-bundle location references remain supported. |

For a selected native local authority, `scripts/gen-astrolift.py --contract contract.json --native-private-volume` requires private persistence and exactly one replica. The explicit flag selects the native mount; it does not move an existing `/data` database. A custom image must honor the same `BRAIN_ROOT` and private-state placement. A local files authority supplies a native snapshot/reference, rather than a new mutable file journal.

The S3 adapter uses Boto3's default credential chain. The host can provide workload identity through `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`, with a grant limited to the selected bucket and prefix. The generator emits location and region reference names without resolving values, credentials, or identity tokens. The SDK chain also permits static credentials if supplied by the host, so this is not enforcement of a workload-identity-only chain. An unbound bucket remains unavailable until the host establishes its binding; generation does not provision or qualify a bucket.

## Moving canonical authority

Changing a deployment persistence setting, DSN, or edition reference does not migrate records or activate a new authority. In this edition, brains that have adopted retained-content storage admission refuse `init`, `restore`, `cutover`, `resume`, and `migrate` before effects. The following steps apply to supported routes without that storage-admission adoption; native authority adoption is a separate boundary.

Files, SQLite, and PostgreSQL transitions use the native operator workflow:

1. Identify the current canonical writer. Obtain a complete native snapshot, its history declaration, and verified referenced blob bytes. A legacy source folder requires a separately reviewed import; unknown prior history stays unknown.
2. Provision a distinct successor store and adapter. Validate its cell, private permissions, and host identity. Keep the source and destination connection references separate.
3. For an existing native authority, use `scripts/knowledge-store.py cutover --to STORE`. Initial adoption requires explicit reviewed initialization instead. The native workflow checks snapshots, bindings, blob placement, and writer state; it freezes the source and permits one active successor. After interruption, use `resume --to STORE` to reconcile the recorded transition.
4. Verify authorized record/context equivalence, complete history, successor state, and source freeze. Then update the adopted connection and host registration and refresh the appropriate projections.
5. Preserve both sides and reconcile failures before successor writes. After successor writes, stop writers and use an explicitly approved reverse transfer/cutover if needed; a stale source cannot be reactivated as rollback.

Missing blobs, stale snapshots, mismatched bindings, unsupported cells, uncertain writer state, or unverified destination state refuse the transition. Independent stores have no shared transaction, and an Astrolift metadata update cannot bypass the native policy, identity, review, or cutover gates.

## Storage admission and selected native operations

The selected admission source covers bounded logical inventory and reservations for specified local writer routes. `aggregateCapacity.available` remains false; this is not a physical disk, filesystem, WAL, or memory limit. Protected attachments require the selected per-record provider route and current host/policy checks.

The local owner install operation applies an exact reviewed App bundle to an adopted local SQLite brain as a disabled draft. It does not enroll, serve, or grant access, and it is not exposed through Studio Apps JSON-RPC or bearer-token permissions. A trusted maintenance host can capture a protected snapshot on its declared retained-content route when its adapter and policy checks pass. Neither operation proves that a deployment has been integrated or qualified.

The selected v10 backup route supports one host-registered local SQLite authority and local-files destination for supported no-blob or database-blob snapshots. Adopted/protected sources, external filesystem blobs, remote destinations, multi-store atomicity, and general PGlite restore remain outside that route.
