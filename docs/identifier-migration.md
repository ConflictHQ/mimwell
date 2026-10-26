# Reviewed JSON identifier migration

These are explicit operator tools, separate from ordinary builds and template
updates. They preview selected current plain JSON files, save exact preimages and
apply only a reviewed plan while the operator keeps all writers stopped. They do
not walk a brain, rewrite native records or retire existing compatibility readers.

`scripts/migrate-identifiers.py --kind schema-root` renames only the root
`x-conflict` JSON Schema annotation to `x-mimwell`. Its `--kind kg` scope and
`scripts/migrate-kg.py` restamp supported legacy or explicitly selected headerless
KG roots as `mimwell-kg/v1`. Every other UTF-8 byte, node/edge ordering, identity,
parallel edge and envelope property stays exact. A present unknown/null marker,
both schema annotations, duplicate keys, invalid Unicode or nonfinite numbers
refuse. An already current file retains its exact bytes and inode.

Do not select frozen schemas, release catalogs, signed/checksummed containers,
receipts, native databases, CLI journals or authority records. Recognized
integrity-bound containers refuse, but the operator remains responsible for file
ownership and scope. There is no recursive identifier replacement and no new
content-version transform or authority migration in this selection.

The mutation profile requires local POSIX no-follow descriptor operations,
nonblocking file locks, file/directory fsync and supported metadata inspection.
Supported adapters target Darwin and 64-bit Linux x86_64/aarch64; other platforms
or missing primitives refuse. This is not Windows in-place migration. Use physical
paths, such as `/private/tmp` rather than a macOS `/tmp` symlink. Symlink components,
nonregular/hardlinked files, foreign ownership and unsupported ACLs, xattrs or inode
flags refuse. The tools preserve UID, GID and mode; they do not strip metadata.

Create an operator-owned `0700` directory outside served files and source repos.
Plans, journals and raw preimages disclose selected paths and content; new files
are private `0600`. Existing output names and permissive metadata directories
refuse. Limits are 128 files, 64 MiB input/output and 4 MiB plan/journal metadata.

```sh
mkdir -m 700 /physical/private/operator-migration
python3 scripts/migrate-identifiers.py --kind schema-root \
  /physical/brain/schemas/current-owned.schema.json \
  --plan /physical/private/operator-migration/schema-plan.json
python3 scripts/migrate-kg.py /physical/brain/app/knowledge_graph.json \
  --plan /physical/private/operator-migration/kg-plan.json
```

Preview does not write selected inputs. Review exact paths, pointers, preimages,
proposed hashes, metadata and the displayed plan SHA. Stop every selected writer,
including generators, editors, Studio and independent processes, throughout apply
and verification/recovery. `--attest-quiescent` records that assertion; the tool
cannot discover arbitrary writers or provide a kernel compare-and-swap against
an uncooperative process.

```sh
python3 scripts/migrate-identifiers.py \
  --apply-plan /physical/private/operator-migration/schema-plan.json \
  --plan-sha256 REVIEWED_PLAN_SHA256 \
  --state-dir /physical/private/operator-migration/recovery \
  --attest-quiescent
```

Use `migrate-kg.py` with its own reviewed plan for a KG. Apply/recovery select files
only from that plan; do not append positional paths. The public Make targets are
thin wrappers: `make migrate-identifiers FILES= ARGS="..."` and
`make migrate-kg KG= ARGS="..."`. Their path defaults are empty. Explicitly clear
`KG=` during reviewed actions so a previous command-line value cannot add a path.
The obsolete `--apply` shortcut refuses.

On interruption retain the private recovery directory and all evidence. Inspect
its journal, then choose `--resume /physical/private/operator-migration/recovery`
or `--restore-preimages /physical/private/operator-migration/recovery`, with both
`--plan-sha256 REVIEWED_PLAN_SHA256` and `--attest-quiescent`. Recovery checks the saved
implementation, intended metadata, current file identity and byte hashes. It
restores only unchanged tool-written postimages and does not roll back unrelated
edits. Multi-file publication is resumable, not an atomic batch. Ambiguous,
foreign or replaced evidence remains for operator reconciliation.

The migration helper dynamically loads the selected `scripts/build-kg.py`; its
`kg_evidence.py` and `kg_identity.py` dependencies are included too. This keeps the
KG identifier tied to the existing generator rather than a second format rule.
No build runs these mutation commands automatically, and packaging the tools does
not qualify a user's filesystem, native authority or migration plan.
