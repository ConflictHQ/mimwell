# Native app publication

Mimwell can expose an optional native app receiver. It is disabled by default. Enabling it requires an operator to provide the complete receiver configuration and the host's existing native bearer credentials, bound to the intended brain and environment. This setting does not create credentials or grant app access.

The receiver validates the current publication descriptor, bundle digest, and identity bindings. That validation does not establish that a person reviewed the entry. Keep the bundle root and publication registry private to the host.

The owner-mediated installer produces a disabled draft. Staging a bundle preserves the enabled value declared in that bundle; staging itself does not enroll an app, activate the receiver, or grant access. Publishing files does not change those authorization boundaries.

The publication registry and receiver configuration must agree on app identity, bundle digest, brain identity, and environment identity. Missing, stale, or mismatched values must fail closed. Keep operational credentials out of bundles and public edition files.

A source selection or staged package does not qualify a host deployment, establish capacity coverage, or enable aggregate storage guarantees. See [Native capabilities](../native-capabilities.md) and [Storage admission](../storage-admission.md) for the edition's current boundaries.
