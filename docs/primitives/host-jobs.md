# Host-invoked build and ingest

Run `python3 scripts/brain-rebuild.py --root /source --mode build` to preview a
job. Add `--execute --output /work/job` to execute it. The output directory
must not exist and must be outside the source checkout. Use `--mode ingest` and
`--recordings /input/recordings` for precomputed recording folders.

The host checks out the repository and provisions its credentials before this
entrypoint runs. The job requires an exact clean standalone Git source, creates
a private detached clone, and runs `make build` or `make ingest` in that clone.
It leaves the original source unchanged and retains generated outputs for host
review. It never commits, pushes, deploys, approves a proposal or replaces a native
authority writer. The JSON `commit` field identifies the input source commit.

Standard output is one JSON summary with `status`, `records`, `changed`, `commit`,
`executed` and `outputsRetained`. Exit zero means successful execution or preview;
a refused or failed job exits nonzero. Failed or unknown record counts remain
null. Private bounded stage diagnostics are retained in the output directory.

The default process deadline is 900 seconds; `--timeout` accepts 1–3600 seconds.
Individual Git commands are bounded to 30 seconds. Source and recording limits
are enforced, including refusal of links and Git submodules. The host supplies
quiescent inputs, volume quotas and an OS isolation boundary; process groups do
not sandbox untrusted engine or provider code or impose a universal disk I/O
deadline.

The separate one-off worker can be built with
`docker build -f runtime/rebuild-job/Dockerfile -t <worker> .`. It includes Python,
Git, Make and the hashed portal base requirements. Optional Drive and transcription
clients belong in an operator-controlled derived image. Run with a read-only
source mount, a private writable output volume owned by the selected nonroot UID,
and the resource/network limits appropriate for the configured provider.

Credentials are not inherited wholesale. Select each required variable with
`--pass-env NAME`; for example, a configured provider may require
`--pass-env OPENAI_API_KEY`. The host resolves its own secret references and never
passes secret values on the command line. Git, Python, loader, HOME and brain
control environment overrides are refused. Repository authentication is not
needed by this local job because it performs no remote fetch or commit-back.

`make ingest` runs the ordered recording stages and refuses an absent eligible
recording graph. The default scaffold does not fetch data or enable a provider.
Configure those sources explicitly before using them. The GitHub refresh workflow
remains a separate CI path. Native capture/proposal/review/commit operations remain
the declared route for native authority changes.

See [container status](host-status.md) for public deployment declarations. This job
does not automatically update those declarations or prove authority health.
