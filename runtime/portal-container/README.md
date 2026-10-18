# Portal container

One image that serves a brain on a container host such as Astrolift:

| Path | Served by | What |
|---|---|---|
| `/` and every published file | nginx proxies to the Python access gate | the brain's published asset set (`_site/`), scoped per request using the same access rules as the Worker |
| `/health` | nginx | `ok`, for the platform's health check; up only once `/mcp` is |
| `/.well-known/mimwell.json` | nginx proxies to the Python host | versioned public deployment facts; unknown values stay null; no native inventory |
| `/mcp` | nginx, then gunicorn on loopback | the brain as an MCP server (`scripts/brain_mcp.py`, #459) |
| `/api/*` | nginx | `503`: chat (`/api/chat`) is a Cloudflare Worker feature |

Port 8080, user 10001, no writable path outside `/tmp`. Either process exiting ends
the container, so the platform restarts it whole.

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

## Who the caller is

| Environment | Default | Meaning |
|---|---|---|
| `BRAIN_MCP_JWKS_URL` | unset | the install's JWKS, e.g. `https://<install>/api/brains/v1/jwks.json` (https; plain http only to a loopback host) |
| `BRAIN_MCP_ISSUER` | unset | the tokens' `iss`: the install's URL |
| `BRAIN_MCP_AUDIENCE` | unset | the tokens' `aud`: this brain's Astrolift app id |
| `BRAIN_MCP_TOKEN_HEADER` | `X-Astrolift-Brain-Token` | the header the token travels in |
| `BRAIN_MCP_ALLOWED_ORIGINS` | none | comma-separated origins a request may carry in `Origin`; any other gets `403`. No CORS headers are sent, so a page on another origin still cannot read the reply |
| `BRAIN_MCP_PUBLIC_ONLY` | `false` | explicitly selects the complete legacy published projection as public; it cannot be used with an adopted authority |
| `BRAIN_OPERATIONS_ROOT` | `BRAIN_ROOT` | private root holding the operations host and MCP identity mapping |
| `BRAIN_OPERATIONS_HOST` | `_internal/knowledge-operations.json` | protected native operations host, needed only for proposals |
| `BRAIN_MCP_ENABLE_PROPOSALS` | `false` | expose the optional native review-queue proposal tool |
| `BRAIN_STATIC_IDENTITY_SOURCE` | `anonymous` | `anonymous`, `token`, or `edge`; controls the identity used for static files |
| `BRAIN_STATIC_EDGE_SECRET` | unset | required with `edge`; host-injected assertion that proves the email header came from the authenticated edge |

With the three verification settings, every request needs a valid Astrolift brain
read token (ES256, the install's key, `iss`, `aud`, unexpired, scope `brain:read`),
and the token's `email` is the identity the access rules see; an app's token has
none and reads as a reader. Missing or invalid: `401`. Keys unreachable: `503`,
retried after 30 seconds. Setting only some of the three refuses to start.

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
