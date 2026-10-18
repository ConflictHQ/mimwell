# Storage routing

Mimwell uses explicit storage contracts and host registrations. A connection or
destination is never selected from a folder name, and a failed route does not
fall back to another store.

## Current reference behavior

The current local reference scenario has one native record and journal authority,
at most one binary-blob store, and multiple explicitly selected source folders.
Record locators bind binary bytes to one store ID, relative key, digest, size and
media type. Source-folder adapters preserve path identity and do not write back
to those source folders. Separate native authority aliases remain independent:
each request selects one registered authority, and writes do not fan out or form
a cross-database transaction.

Native projections use a different route. An authenticated host registration
selects a private projection destination and principal. The client previews the
projection, pins its digest, and asks the host to deliver it; the native writer
rechecks the selected registration and sink before acknowledging delivery. This
projection destination is not configured as a `brain.stores[]` role.

The routing matrix and current source-level reference are listed in
[`substrate-cells.json`](../substrate-cells.json). This reference scenario is not
Astrolift's selected deployment topology. Its owner has not chosen whether the
Astrolift pilot will use one record database with filesystem locations or more
than one record database.

## Not currently qualified

The native contract accepts at most one record/journal authority and one blob
store for the relevant roles. It does not transparently shard record writes
across databases, route one role to multiple blob pools, or provide a distributed
transaction across authorities.

The export command can return a native snapshot to standard output, and snapshot
capture has a separately selected destination flow. No contract store ID binds a
durable backup destination, so neither behavior qualifies as contract-routed
backup storage. A future backup route needs a versioned host-owned destination
registration, authority and snapshot pins, route revalidation, secret-free
receipts, and explicit preview/apply adoption. Its supported destination drivers
and Astrolift topology remain pending owner selection.

Store and source references may name environment variables, but manifests and
receipts must not contain resolved credentials or secret values. Public packages
ship selected configuration schemas and code, not deployment secrets or a claim
that a particular Astrolift topology has been approved.
