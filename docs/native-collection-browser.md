# Browse a selected native collection

The optional knowledge workbench can list a selected SQLite collection and open
a listed record in the existing canonical editor. It is an operations-host
capability, separate from MCP tools and from the existing `record.get` contract.
Installing this code does not create a host, grant access or select a writer.

An operator explicitly selects `knowledge-operations-host/v11` and authorizes
`collection.browse`, `authority.inspect` and `record.get` for an existing
principal. The host retains its current registration, native binding, policy,
credential and owner checks. Requests cannot supply paths, policy or identities.
The public scaffold contains no enrolled host or private catalog. PostgreSQL,
MySQL and file/publication-group writers do not acquire this browser capability.

Requests use `knowledge-operation-request/v13`; results use
`knowledge-operation/v13`. `collection.browse` takes exactly `collection`,
`limit` (1–100) and `cursor` (null or the exact returned cursor).
`native-collection-page/v1` contains only readable ordinary-context record IDs,
kinds, titles, revisions, whole-record editability and the next cursor. It does
not report hidden counts or scan positions. Bounded work can produce a short or
empty page with a continuation; that does not imply an empty collection.

Cursors bind the actual native instance, policy, registration, principal,
collection, committed journal basis and membership time. They expire after five
minutes. A pending proposal does not change the committed journal. A committed
change, changed registration or different authority invalidates old cursors.
Every continuation still checks current read access; a cursor never grants it.
These are bounded navigation snapshots, not an atomic multi-request view or a
guarantee against arbitrary database rollback or hostile filesystem mutation.

The workbench first discovers the selected writer through its existing route.
It offers browsing only when the freshly inspected host reports v13. Selecting a
row checks the original page and then performs canonical `record.get` at the
listed identity, collection and revision. Denied, stale and changed-owner
responses do not release record content or enable a write. Editing still uses
the existing proposal, independent review and commit lifecycle.

An operator must supply independently reviewed compatible host, schema, policy
and writer declarations. No private recipe/discovery/interface registry,
credentials, guidance projection or live-host acceptance evidence is bundled.
The schemas and source entrypoints describe the API; `make verify` on the empty
public scaffold does not qualify an enrolled host or its data.
