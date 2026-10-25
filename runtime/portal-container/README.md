# Portal container

One image that serves a brain on a container host such as Astrolift:

| Path | Served by | What |
|---|---|---|
| `/` and every published file | nginx proxies to the Python access gate | the brain's published asset set (`_site/`), scoped per request using the same access rules as the Worker |
| `/health` | nginx | `ok`, for the platform's health check; up only once `/mcp` is |
| `/.well-known/mimwell.json` | nginx proxies to the Python host | versioned public deployment facts; unknown values stay null; no native inventory |
| `/mcp` | nginx, then gunicorn on loopback | the brain as an MCP server (`scripts/brain_mcp.py`, #459) |
| `/apps[/<app-id>]`, `/brain/{record,revision,context,records/<kind>}` | nginx, then the optional third gunicorn worker on loopback | the native App host, only when the operator enables `BRAIN_PORTAL_NATIVE_APPS=1` with the complete private host configuration |
| `/.well-known/mimwell/native-record` | nginx proxies to the Python host | one current native record as escaped HTML, only when the separate reader is explicitly enabled |
| `/api/*` | nginx | `503`: chat (`/api/chat`) is a Cloudflare Worker feature |

Port 8080, user 10001, no writable path outside `/tmp`. The default image starts
the MCP worker and nginx. The optional native App worker binds only to loopback
port 8082; startup enables its fixed route include only after the worker answers
the unauthenticated readiness request with the expected 401. If any enabled
worker exits, the other children are stopped and the platform restarts the
container as a unit. The app routes are absent when the feature is disabled.

The portal container can host the existing `context_service:create_application()`
factory as the optional third worker. It reuses the existing native `AppBackend`
authentication and authorization path; it does not create a new grant, identity
mapping or enrollment. Enable it only with `BRAIN_PORTAL_NATIVE_APPS=1` and the
complete V7 receiver configuration: `BRAIN_APPS_HOST`, `BRAIN_CANON_DSN` or
`BRAIN_CANON_DSN_FILE`, `BRAIN_CONTEXT_CREDENTIALS`, `BRAIN_APP_BUNDLE_ROOT`,
`BRAIN_OPERATIONS_ROOT`, `BRAIN_APP_PUBLICATION_REGISTRY`,
`BRAIN_APP_HOST_BRAIN_ID`, `BRAIN_APP_ENVIRONMENT_ID`, and the fixed
`BRAIN_APP_BROWSER_PROXY_PREFIX=/api/native-brain`. Supplying native app settings
without the explicit switch fails startup. The proxy worker is loopback-only;
nginx routes only `/apps`, one app-id path, the three fixed `/brain` endpoints,
and one `/brain/records/<kind>` segment. Native-route access logging is disabled
to avoid recording record addresses from query strings.

This change does not stage or install a private bundle. An operator must provide
separate private bundle and operations roots, each owned by UID 10001 and closed
to group/other access; the bundle root's `apps/` directory has the same private
mode requirement. The existing local installer target can have public-readable
parent modes, so it cannot be used directly as the V7 bundle root. A future
stager must copy the selected reviewed bytes into a separate private volume,
verify the exact `brain-app-bundle/v1` digest and installed file modes, and must
not chmod or normalize bundle files after digest calculation. Do not enable the
worker until that private staging and publication registry are provided and
reviewed. Bundle staging, publication activation, credentials, the native
database and the operations registry are not baked into the image.

```sh
# from the brain's root
docker build -f runtime/portal-container/Dockerfile -t <image> .
docker run -p 127.0.0.1:8080:8080 <image>
```

The build stages `_site/` with `scripts/build-portal-site.py` from the build
context, indexed afresh (`.gitignore` keeps local files out, `.assetsignore` keeps
internal ones out of `_site/`), so the image publishes what the Worker would. A
local build therefore includes untracked files that `.gitignore` does not exclude.
`Dockerfile.dockerignore` keeps `.git`, secrets and the recordings working area out
of the build context.

The optional `engine.brain-mcp-service` catalog package records file ownership and
planning dependencies; it does not assemble a component-only build tree. The
canonical build context is the complete installed template at the brain root.
`scripts/init.py` copies that complete template, while recipe selection only stamps
the selected brain configuration. The Dockerfile copies the full source tree,
scripts and schemas, so a tree containing only the package's listed files is not a
supported image build context. The source checkout's `.git` is excluded and is not
image provenance: the build stage creates a synthetic Git index from the context
to stage the published asset set. This package does not assert a source commit or
qualify a built or deployed image.

Astrolift may supply the reserved `ASTROLIFT_SOURCE_COMMIT` build argument when
the deployment's saved commit, build input and immutable source URL all match.
The host must enforce that equality before provisioning the build; the image
builder only validates that a non-empty value is a full lowercase SHA. After
`_site/` has been staged, the build records that host-supplied commit with the
SHA-256 of the exact `_site/app/brain.json` bytes in a small versioned receipt
outside `/srv/brain`. It also writes a private, bounded file-byte manifest from
that same staged `_site/` tree, covering the graph, knowledge pack, schema and
safe document-path candidates that are actually published. Document coverage
is marked partial if scanning, path validation or size limits prevent a complete
inventory.
The fixed files are limited to 64 MiB each; document candidates to 8 MiB each;
the aggregate bound is 256 MiB, with at most 4,096 paths and a 1 MiB manifest.
The runtime copies both files root-owned and read-only into
`/opt/brain/private/`; it checks the graph receipt against the same graph bytes
parsed at startup and checks other entries against the raw bytes when those
files are read. A malformed graph receipt or graph mismatch prevents startup.
An absent or mismatched artifact manifest leaves this internal byte evidence
unavailable and does not alter read authorization or output. With no argument,
neither file is written and legacy image builds continue without this evidence.

This is host-attested file-byte evidence, not proof that the staged files came
from the named Git object or a transactional source-tree snapshot. It identifies raw
file bytes, not the processed text returned after access filtering or
truncation. It does not bind native authority revisions or independently attest
the deployed image. It is not a citation contract and is not returned by `/mcp`
or the public status document. In particular, neither the synthetic Git index
nor an operator-declared public `revision` is used as source provenance.

The [status document](../../docs/primitives/host-status.md) has no extra MCP token
requirement beyond the deployment edge. Private/native counts remain unknown.
Set `BRAIN_PUBLIC_STATUS` only for an explicit private operator file containing
facts intended for public status. Those facts are labeled `operator-declared`;
status availability does not establish authority health or ingestion success.

## The MCP endpoint

Streamable HTTP, protocol 2025-06-18 (and 2025-03-26), one JSON-RPC message per
POST, a JSON reply per request and `202` per notification. Stateless: no session id
and no server-to-client stream, so `GET` and `DELETE` answer `405` and any replica
answers any request.

| Tool | Answers |
|---|---|
| `search_records` | ranked records (id, kind, title, summary, source) and documents (path, title, summary) for a keyword query; `kind` narrows to one record kind or `document` |
| `read_record` | one record with its relationships, by `id`, or one document's text, by `path` |
| `list_definitions` | glossary terms, metrics, and the record kinds with how many of each the caller can read |
| `resolve_metric` | a metric's definition record by name, alias or id; listed only when the caller can read a `Metric` record |

By default the HTTP server exposes only read tools. `propose_change` is available
only when an operator explicitly enables it and configures its private native
operations host.

For legacy file brains, verified HTTP token identities or the local stdio host map
are required. An operator may select `BRAIN_MCP_PUBLIC_ONLY=true` for a legacy brain
whose complete published projection is intentionally public. This setting is refused
when a native authority is adopted. With a native authority, the server requires a
private, authority-bound identity map and checks each compiled record against the
live native record policy before returning it. Documents without a native record
binding are withheld. Native metric execution also checks the metric's live policy.

For ordinary file-brain access, the brain's own `access` rules from
`client.config.json` decide what each caller gets, exactly as the Worker decides it
(`scripts/access_gate.py` is the Python twin of `access.js`; a parity test holds them
together). A Worker tool withheld from non-owners by `access.restricted_tools`
(`search_graph`, `search_knowledge`, `read_doc`) also withholds the MCP tool that
serves the same data, and the MCP tool names can be restricted themselves. Record
rules composed in a local Worker entry (`extensions/_internal/worker.js`) are Worker
code; this endpoint cannot apply them, so a brain that depends on them should not
serve those records from this container. An authority read live goes through the
context service, not the compiled asset set.

## Local stdio transport

Local clients can launch `python3 scripts/brain-mcp-stdio.py`. It speaks one
newline-delimited JSON-RPC message per line and writes protocol responses only to
stdout. Logs and startup errors go to stderr. The process obtains its OS UID from
the host; no MCP argument or environment variable can choose the caller.

Unless explicit public-only mode is selected for a legacy brain, the UID must map
to an identity in the operator-owned, mode-0600 file
`BRAIN_OPERATIONS_ROOT/_internal/mcp-identities.json` (the `_internal` directory
must be owner-only). The file has this shape:

```json
{
  "format": "mcp-identities/v1",
  "authorityBinding": null,
  "principalsByIdentity": {},
  "principalsByUid": {"10001": "reader@example.test"},
  "fileSourcesByIdentity": {}
}
```

For an adopted authority, set `authorityBinding` to the configured authority
binding and map the UID to its native policy principal. Verified HTTP email
identities use `principalsByIdentity`; their mapping must resolve to a native
principal too. `fileSourcesByIdentity` may explicitly bind a principal to exact
`app/` catalog files by SHA-256, for example `{"alice@example.test": {"app/catalog.json": "<64 hex digits>"}}`.
The MCP reader verifies the file bytes and the exact node and edge values against
that pinned JSON. There is no default file-source grant. Missing, malformed, or
mismatched mappings fail closed. For
`propose_change`, the UID must also be listed by the protected knowledge operations
host with the `proposal.propose` grant. The private operations host and native
identity file live outside `_site/`; do not mount them into the published site.
The token email is never used as a native actor directly: proposal writes use the
mapped principal, and the mapping is rechecked before returning a response.

## Optional native record page

The current native record page is a separate, opt-in `GET`/`HEAD` route. It is
disabled unless `BRAIN_NATIVE_RECORD_IDENTITY_SOURCE` is set to `token` or `edge`.
It returns only one current record when its requested `id` and exact current
`revision` are readable by the mapped native principal. Missing, unreadable,
stale, and oversized records share a generic `404`. It does not expose history,
the compiled graph, or a record file, and it does not change `/mcp` or static-file
identity behavior.

In `token` mode, the route uses the configured verified brain-read token and
`BRAIN_MCP_TOKEN_HEADER`. In `edge` mode, configure
`BRAIN_NATIVE_RECORD_EDGE_SECRET` and have the trusted gateway overwrite both
`X-Auth-Request-Email` and `X-Portal-Auth-Assertion`; the latter must contain the
configured secret. This is a shared cluster assertion, not a per-app identity
credential. The container must remain reachable only through that gateway, the
secret must remain confidential, and the operator must independently verify
that direct access to the backend Service is blocked. Do not accept these
headers from an untrusted direct client. This is a generic configured edge
assertion, not per-app Envoy `identity_headers` support. Astrolift's app
NetworkPolicy is opt-in; this repository has not verified that a particular
deployment blocks direct Service access. Native-record edge
mode remains disabled by default and is not activated by this change.
The native record reader has its own identity-source setting; it does not relax
the separate static-file identity-source/verifier rules. The response is escaped,
bounded, `no-store`, and sent with a restrictive content security policy.

## Who the caller is

| Environment | Default | Meaning |
|---|---|---|
| `BRAIN_MCP_JWKS_URL` | unset | the install's JWKS, e.g. `https://<install>/api/brains/v1/jwks.json` (https; plain http only to a loopback host) |
| `BRAIN_MCP_ISSUER` | unset | the tokens' `iss`: the install's URL |
| `BRAIN_MCP_AUDIENCE` | unset | the tokens' `aud`: this brain's Astrolift app id |
| `BRAIN_MCP_TYPED_PRINCIPALS` | `false` | explicit opt-in to consume signed contract-1 GUID read principals |
| `BRAIN_MCP_EXPECTED_ORG_GUID` | unset | exact canonical organization GUID required when typed-principal opt-in is enabled |
| `BRAIN_MCP_TOKEN_HEADER` | `X-Astrolift-Brain-Token` | the header the token travels in |
| `BRAIN_MCP_ALLOWED_ORIGINS` | none | comma-separated origins a request may carry in `Origin`; any other gets `403`. No CORS headers are sent, so a page on another origin still cannot read the reply |
| `BRAIN_MCP_PUBLIC_ONLY` | `false` | explicitly selects the complete legacy published projection as public; it cannot be used with an adopted authority |
| `BRAIN_OPERATIONS_ROOT` | `BRAIN_ROOT` | private root holding the operations host and MCP identity mapping |
| `BRAIN_OPERATIONS_HOST` | `_internal/knowledge-operations.json` | protected native operations host, needed only for proposals |
| `BRAIN_MCP_ENABLE_PROPOSALS` | `false` | expose the optional native review-queue proposal tool |
| `BRAIN_STATIC_IDENTITY_SOURCE` | `anonymous` | `anonymous`, `token`, or `edge`; controls the identity used for static files |
| `BRAIN_STATIC_EDGE_SECRET` | unset | required with `edge`; host-injected assertion that proves the email header came from the authenticated edge |
| `BRAIN_NATIVE_RECORD_IDENTITY_SOURCE` | `off` | `off`, `token`, or `edge`; independently enables the single-record native HTML route |
| `BRAIN_NATIVE_RECORD_EDGE_SECRET` | unset | required in native-record `edge` mode; host-configured assertion value for `X-Portal-Auth-Assertion` |

With the three verification settings, every request needs a valid Astrolift brain
read token (ES256, the install's key, `iss`, `aud`, unexpired, scope `brain:read`),
and, by default, the token's `email` is the identity the access rules see; an
app's token has none and reads as a reader. Missing or invalid: `401`. Keys
unreachable: `503`,
retried after 30 seconds. Setting only some of the three refuses to start.

Typed read principals stay disabled by default. To enable them for one brain,
set `BRAIN_MCP_TYPED_PRINCIPALS=true` and its exact
`BRAIN_MCP_EXPECTED_ORG_GUID`. The consumer then accepts only signed `contract`
`"1"` claims with `sub_kind`, matching `org`, and canonical lower-case GUIDs in
`teams`; `agent` and `app` GUID claims are required only for their matching
subject kind. Rules may name `team:<GUID>`, `agent:<GUID>`, or `app:<GUID>`.
Malformed or unknown explicit contract claims are rejected without falling back
to email. Legacy tokens with no typed-contract claims keep their existing
subject/email behavior. The existing token-size ceiling bounds parsing locally;
this does not establish an issuer-side team-count guarantee. Typed principals
are read visibility only. Native identity mappings and operation grants remain
unchanged, and workload/app tokens do not become native actors through an
optional email claim.

With none of them, `/mcp` refuses requests unless `BRAIN_MCP_PUBLIC_ONLY=true` is
explicitly set for a legacy file brain. A reverse proxy that authenticates callers
must configure token verification here or use a separate trusted adapter; a forwarded
email header is not accepted as MCP identity.

Static files are checked per request by the Python host. The default static
identity is anonymous; client supplied email headers are ignored. Set
`BRAIN_STATIC_IDENTITY_SOURCE=token` to use the same verified brain token as MCP.
For an authenticated reverse proxy that supplies an email instead, explicitly
set `BRAIN_STATIC_IDENTITY_SOURCE=edge` and `BRAIN_STATIC_EDGE_SECRET`. The
proxy must remove any incoming `X-Auth-Request-Email` and
`X-Portal-Auth-Assertion` headers, set the email from its authenticated session,
and set the assertion to the secret. Keep the container reachable only through
that proxy; a fixed header without a host-enforced secret is not authentication.
The identity source and edge secret are loaded when the process starts. The
published access rules are part of the image's built asset snapshot. After
changing either the access rules or these identity settings, build a reviewed
image and restart the container before serving requests under the new policy;
this reference does not reload policy files live.

When a native authority is adopted, all static asset routes return `404`,
including the graph, knowledge pack, and raw documents. Static publication has
no native-aware per-record authorization contract yet; use the MCP endpoint,
which checks each record against the live native policy. This refusal applies
regardless of the static identity source or supplied headers.

For non-owners, restricted paths return `404`. `client.config.json` never
includes the `access` block and inaccessible deep links are removed. Compiled
graph, knowledge-pack, manifest and other known artifacts are filtered to the
requester's view. Generic JSON that mentions a restricted path is withheld.
Activity entries sourced from restricted files are omitted or reduced to their
public file rows with generic text.

The token is never logged: nginx logs the request line and status only, and the
endpoint logs no request data.

## Sizing

About 40 MiB at rest for a small brain. Records are read and indexed once at
start; a 20,000-record brain (a 10 MB `app/brain.json`) used about 250 MiB, answered
`initialize` and `read_record` in milliseconds and a search in about 300 ms. Give
the workload room for its brain: the 64 MiB a static nginx portal needs is not
enough.
