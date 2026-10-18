# Local connector clients

Python, Go and Rust clients validate the same `connector-event/v1` JSONL bytes and
invoke one operator-selected local connector host. The host owns authorization,
registration, checkpoints and native proposal admission. Client validation is a
mechanical preview, not a native approval or permission to select another writer.

Each event preserves exact payload bytes, digest and revision. Its ordering value
is a decimal string, including values above the JavaScript integer range. The
bounded local protocol supports text upsert/edit and empty delete/access-change
payloads. Attachment locators are metadata; the clients do not fetch their content.

## Validate the synthetic fixture

From the edition root:

```sh
PYTHONPATH=connectors/python python3 -c 'from pathlib import Path; from connector_sdk import plan; print(plan(Path("connectors/fixtures/events.jsonl").read_bytes()))'
go -C connectors/go run ./cmd/connector-sdk validate --file ../fixtures/events.jsonl
cargo run --locked --manifest-path connectors/rust/Cargo.toml -- validate --file connectors/fixtures/events.jsonl
```

Go requires version 1.23 or later, as declared in `go.mod`. Rust requires a
compatible toolchain; its dependencies follow the shipped Cargo lock. These
commands validate local fixture data and do not submit it to a brain.

## Submit an independently registered export

An operator first selects a private brain root, native authority alias and host
configuration, then registers the exact namespace, local export path and SHA-256.
Neither event fields nor client validation can create or widen that registration.

The Python `HostClient` takes explicit `python`, `host_script`, `root`,
`host_config`, `authority`, `namespace` and `export` arguments. Its `submit()`
returns the exact host receipt bytes. `submit_stdin()` additionally observes
descriptor zero, which must match the independently registered file exactly.

Go and Rust provide `validate`, `plan`, `submit`, `resume`, `status` and `replay`
commands. Supply the same explicit host options for a submission; `submit --stdin`
and `resume --stdin` opt into matching-stdin admission. Run a CLI from the brain
root or supply absolute operator-selected paths so changing the working directory
cannot select another host or export by accident.

Successful admission creates pending native proposals. It does not independently
review, commit or deliver them. Resume and replay retain the host's registration,
identity and event-ledger checks. The clients bound host output and execution time,
preserve native receipt bytes, and return errors without a successful receipt when
the host refuses or times out.

No live platform login, webhook, polling, automatic source registration, automatic
review or automatic delivery is provided by these local clients. See
[native capabilities](../docs/native-capabilities.md) for the governing boundaries.
