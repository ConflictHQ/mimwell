# Intake

Intake decides what to do with new material before it enters the brain: keep
it and send it somewhere, skip it, or hold it for a person to look at. It never
writes anything itself. Every decision it makes is a **proposal** that a
reviewer or your own delivery step acts on.

The shipped planner is deterministic. It routes items by rules over their
metadata, makes no model calls and reads no file contents.

## How it works

You describe inbound items with metadata only: an id, where the bytes are, a
digest, a media type, a size and any extra fields you want to route on. The
planner matches each item against your rules, in order, and returns one
decision per item with a full history record: which rule matched, why, the
exact configuration and policy it used, and who asked.

Three files drive it, all operator-owned:

- a **configuration** with a taxonomy of labels, the routing rules and the
  destinations;
- a **host file** that pins the configuration, the read policy, the bindings
  and the scopes by SHA-256, so a changed file is refused rather than used;
- a **request** listing the items to plan.

The read policy and bindings are the same ones the
[context API](context-api.md#1-a-read-policy) uses. Each item must be bound,
under `references` in the bindings file, to a policy resource the actor may
read. The binding key is the item's canonical fingerprint
(`knowledge_policy.fingerprint(item)`). An unbound item comes back with
`"status": "unavailable"` and no decision.

```json title="_internal/intake/host.json"
{
  "protocolVersion": "1.0",
  "policy":     { "path": "_internal/context/policy.json", "sha256": "<file sha256>",
                  "ontologySha256": "<sha256 of brain-schema.json>" },
  "bindings":   { "path": "_internal/intake/bindings.json", "sha256": "<file sha256>" },
  "scopes":     ["shared"],
  "intake":     { "path": "_internal/intake/configuration.json", "sha256": "<file sha256>" },
  "completed":  { "path": "_internal/intake/completed.json", "sha256": "<file sha256>" },
  "limits":     { "maxItems": 100, "maxInputBytes": 1048576, "maxOutputBytes": 1048576 }
}
```

`completed.json` holds the receipts of items already delivered; start with
`{}`. Every `sha256` pin in the host file is the plain SHA-256 of the file's
bytes (`shasum -a 256`).

## Configuration

```json title="_internal/intake/configuration.json"
{
  "protocolVersion": "1.0",
  "taxonomy": {
    "id": "inbox",
    "version": "1.0.0",
    "ontologySha256": "<fingerprint of brain-schema.json>",
    "labels": [{ "id": "invoice", "kinds": ["doc"] }]
  },
  "rules": [
    {
      "id": "invoices",
      "conditions": [
        { "field": "mediaType", "operator": "equals", "value": "application/pdf" },
        { "field": "metadata.folder", "operator": "equals", "value": "invoices" }
      ],
      "intent": { "action": "keep", "labels": ["invoice"],
                  "destinations": ["finance-docs"], "processing": "metadata" },
      "reason": "PDFs in the invoices folder are invoices"
    },
    {
      "id": "screenshots",
      "conditions": [{ "field": "metadata.folder", "operator": "equals", "value": "screenshots" }],
      "intent": { "action": "skip", "labels": [], "destinations": [], "processing": "none" },
      "reason": "Screenshots are not kept"
    }
  ],
  "destinations": [
    {
      "id": "finance-docs",
      "target": { "participant": "example", "authority": "files",
                  "collection": "knowledge/docs/finance", "revision": "1" },
      "resource": "shared.doc",
      "mode": "write",
      "kinds": ["doc"]
    }
  ]
}
```

Rules to know:

- Conditions test `mediaType`, `byteLength` or any `metadata.<field>`, with
  `equals`, `prefix` or `atMost`.
- `keep` needs at least one destination and a processing level (`metadata` or
  `extract`). `skip` and `review` take no destinations and `processing: "none"`.
- Labels map to kinds your ontology declares, and destinations name a policy
  resource.
- The taxonomy's `ontologySha256` is the canonical fingerprint of
  `brain-schema.json`, not its file hash:

```bash
PYTHONPATH=scripts python3 -c "
import json; from knowledge_policy import fingerprint
print(fingerprint(json.load(open('brain-schema.json'))))
"
```

## Running it

```json title="_internal/intake/request.json (one item shown)"
{
  "protocolVersion": "1.0",
  "offset": 0,
  "inputSha256": null,
  "budget": { "maxItems": 100, "maxInputBytes": 1048576, "maxOutputBytes": 1048576 },
  "items": [
    {
      "id": "inbox-1",
      "metadata": { "folder": "invoices" },
      "source": {
        "id": "inbox", "revision": "1", "sha256": "<digest of the file>",
        "mediaType": "application/pdf", "byteLength": 20480,
        "reference": { "backend": "fs", "object": "invoices/acme-2026-09.pdf",
                       "locator": "", "availability": "available" }
      }
    }
  ]
}
```

```bash
python3 scripts/plan-intake.py --root . \
  --host-config _internal/intake/host.json \
  --actor coding-agent \
  --request _internal/intake/request.json \
  --output _internal/intake/plan.json
```

`--actor` is the trusted identity of whoever runs the plan; it never comes
from the request. `--output` must be a new file. For the invoice above, the
plan proposes `keep`, labels it `invoice`, and proposes delivery to
`finance-docs`, with `requiresReview: true` and `"mechanism": {"tier": "rules",
"rule": "invoices"}`. The screenshot gets `skip` from the `screenshots` rule.
`usage` reports zero model calls.

Large batches page: when the output budget fills, `nextOffset` tells you where
to resume, and `inputSha256` pins the batch so a resumed request cannot
silently change it.

## Not covered here

The engine also contains model-assisted classification, local document text
extraction and recording transcription. Classification needs a native
classifier and model files that this release does not ship, and extraction and
transcription need host decoders you provide. They are not documented for this
release.
