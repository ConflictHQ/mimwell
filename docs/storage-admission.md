# Storage admission and protected App bytes

This edition selects an opt-in host-managed logical storage admission service for bounded local routes. It is not a complete brain-wide quota. The inspection response reports the measured inventory and reservations; `aggregateCapacity.available` remains false while retained writers or effects fall outside the checked boundary. The measure is not physical disk, filesystem, WAL, or memory capacity.

## Selected routes

The bounded reference inventory reports the selected SQLite authority's native-content inventory; `managedBlobs` bytes from the selected filesystem blob tree or database blob rows; retained App bundle Git history and the current `apps/` worktree; the registered Studio App session root; and every registration's `retainedRoots` entries, each accounted under its `kind:id` class. It does not cover content outside those registered routes. Admission is rechecked at writer boundaries. Unsupported or ambiguous routes refuse. Inspection does not adopt a brain, create a ledger, grant access, or change store configuration.

The selected owner-mediated local App installation operation accepts an exact reviewed source commit and bundle digest for an adopted local SQLite brain. It leaves the installed App disabled as a draft. It does not enroll or serve the App, grant users access, or expose installation through Studio Apps JSON-RPC or bearer-token permissions. This source selection does not itself qualify a host integration or authorize installation on another route.

Protected App attachment chunks and stored bytes are supported only when the selected per-record provider route passes current host and policy checks. The provider seals bytes before durable storage and binds the envelope to attachment context. Transfers to another protected host must be resealed and authorized there. The envelope does not protect native record bodies, history, metadata, or arbitrary files.

A trusted maintenance host may use the selected protected snapshot capture adapter on the declared retained-content route. The ordinary CLI has no adapter and refuses adopted capture. Capture requires the supported per-record profile, opaque metadata disabled, and offline retain authorization. It is capture only; restore, activation, and cutover remain outside this selection.

## Limits and refusals

The host inspection API returns bounded inventory and ledger totals without record content or caller-supplied paths, limits, identities, or grants. A complete response describes only the selected host route. Unsupported profiles, routes, or missing guarantees refuse instead of falling back to plaintext or another store.

General replacement and retention deletion remain outside the selected install and admission boundary. Protected snapshot capture does not prove complete storage admission. SQLite coordination sidecars may be created while opening a read-only authority, so capture does not promise zero filesystem effects.

## Backup route

The existing fixed host-registered local v10 backup flow remains limited to one SQLite authority and a declared local-files destination. It supports the selected no-blob and database-blob cases. Adopted or protected sources, external filesystem blobs, remote destinations, unsupported layouts, cross-database transactions, and general PGlite restore remain unsupported or refuse.

See [storage routing](storage-routing.md), [native capabilities](native-capabilities.md), and [snapshot capture](snapshot-capture.md) for the surrounding route and protection boundaries.

## Coordinated unsupported writers and residue

Selected local native administration checks the configured authority under its
existing native writer fence before unsupported creation, restore, activation,
freeze, migration, cutover or resume effects. Adopted/unknown admission state
refuses those effects; ordinary unconfigured legacy workflows retain their
existing behavior. Configured private alternate destinations and reserved SQLite
sidecar names cannot become unaccounted standby writers.

Inventory refuses unknown nonempty private residue instead of exempting a file
by its basename. The operator host configuration is excluded only after bounded
canonical validation; retained copies use their registered logical accounting
classes. Failed publication does not delete a foreign/replaced ledger or silently
release ambiguous debt. Session retirement and unsupported recovery remain
refusals, not time-based deletion. These cooperative writer fences and
conservative accounting do not qualify aggregate capacity or arbitrary external
filesystem/database writers.
