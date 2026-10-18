# Container deployment status

The portal container serves GET and HEAD `/.well-known/mimwell.json` behind
the deployment edge. This exact route does not require the additional MCP token.
Other methods return 405; `/mcp` retains its authentication. The endpoint is not
available from the static Worker runtime.

The JSON document reports contract `1`, the engine version, nullable deployment
facts, nullable substrate placement, and MCP server read capabilities. Those
capabilities are not a caller's admitted tools; authenticate and use `tools/list`
to discover the current grants. Responses have `Cache-Control: private, no-store`.

Native and authenticated record counts remain null. A legacy deployment explicitly
selecting `BRAIN_MCP_PUBLIC_ONLY=true` can report its anonymous filtered projection
count. Status never opens the native database to count records or measure health.

Unknown edition, compilation time, deployed Git revision and ingestion outcome
remain null. To supply public deployment facts, provision a mode-0600 JSON file
inside the operator-owned mode-0700 `_internal` directory below
`BRAIN_OPERATIONS_ROOT`, and set `BRAIN_PUBLIC_STATUS` to its relative path.

```json
{
  "format": "mimwell-public-status/v1",
  "edition": "mimwell/v0.3.5",
  "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "compiled_at": "2026-10-17T14:00:00Z",
  "last_ingest": {"at": "2026-10-17T14:00:00Z", "status": "ok"}
}
```

These values illustrate the shape; use actual public deployment facts or omit
unknown fields. The server labels them `operator-declared`; it does not verify
deployment or ingestion success. Replace the file atomically and restart the
host to change its declaration. Extra fields, duplicate keys, unsafe permissions,
links and declarations larger than 4096 bytes are refused. Do not include secrets
or private source details in this intentionally public declaration.

See the [portal container](../../runtime/portal-container/README.md) and
[host jobs](host-jobs.md).
