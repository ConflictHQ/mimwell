# Interchange and export

To move a brain's compiled graph between systems, pack it into an exchange
archive. An archive is a self-checking envelope: it records where the data came
from and carries a digest over everything inside, so any change after packing
is detected.

Interchange lives in `scripts/knowledge_interchange.py` and is used from
Python.

## Pack an archive

```python
import json, sys
sys.path.insert(0, "scripts")
import knowledge_interchange as ki

brain = json.load(open("app/brain.json"))
archive = ki.pack(brain, {"id": "example-brain", "revision": "2026-09-26"})
print(json.dumps(ki.inspect(archive), indent=1))
```

`inspect` reports what the archive is and what it is not:

```json
{
  "format": "brain-exchange/v1",
  "sourceFormat": "compiled-brain/v1",
  "origin": { "id": "example-brain", "revision": "2026-09-26" },
  "sha256": "…",
  "fidelity": "exact-json-value",
  "history": "not-present-in-source",
  "validation": "transport-only; destination native schema/replay and policy required",
  "authority": "none",
  "manifest": "absent"
}
```

The origin needs exactly `id` and `revision`. An optional third argument
attaches a manifest, which travels with the archive as a claim of the source,
not as a verified fact.

Two formats exist. `brain-exchange/v1` is the default. `brain-exchange/v2`
computes its digest with RFC 8785 canonical JSON, so other languages can check
it byte for byte:

```python
archive = ki.pack(brain, {"id": "example-brain", "revision": "2026-09-26"},
                  format=ki.PORTABLE_FORMAT)
```

## Check and unpack

```python
payload = ki.unpack(archive)   # validates, then returns the original JSON
assert payload == brain
```

`validate` and `unpack` recompute the digest. Changing any part of the archive,
including its origin, fails with `exchange digest or source format mismatch`.

## Store it in SQLite

```python
ki.write_sqlite("example.exchange.db", archive)   # refuses to overwrite
restored = ki.read_sqlite("example.exchange.db")
assert ki.unpack(restored) == brain
```

The round trip returns exactly the value you packed.

## Project to a plain graph

Some tools only want nodes and edges. `project` gives you that graph plus a
report of what the projection leaves out:

```python
result = ki.project(archive)
graph, report = result["graph"], result["report"]
print(report["losses"])
```

```json
[
  { "path": "/origin",       "reason": "exchange origin and revision require the archive" },
  { "path": "/payload/meta", "reason": "compiled envelope metadata requires the archive" }
]
```

The projected graph is labelled with the `conflict-kg/v1` graph format.

## What an archive does not do

An archive moves data, not permission. Unpacking one grants no access and
proves nothing about who may use it: the destination applies its own schema
checks and its own [read policy](context-api.md#1-a-read-policy). Treat an
archive from someone else as input to review, not as trusted knowledge.
