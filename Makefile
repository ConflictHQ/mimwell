.PHONY: build test verify dev brain-db brain-check brain-d1-push

build:
	python3 scripts/compose-schema.py
	python3 scripts/gen-kinds.py
	python3 scripts/gen-specs.py
	python3 scripts/gen-dependencies.py
	python3 scripts/gen-estimates.py
	python3 scripts/gen-spec-stats.py
	python3 scripts/gen-build-readiness.py
	python3 scripts/gen-knowledge-pack.py
	python3 scripts/gen-docs-manifest.py
	python3 scripts/gen-assets.py
	python3 scripts/ingest_sources.py
	python3 scripts/gen-brain.py
	python3 scripts/brain-sqlite.py sync
	python3 scripts/gen-staleness.py
	python3 scripts/gen-manifest.py

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 -m unittest discover -s tests

verify: build test
	python3 scripts/validate-schemas.py

dev:
	npm run dev

# Compiled-store encodings (#439). brain.store in client.config.json picks the
# store: "json" (default), "sqlite", "both" or "d1". `make build` already runs
# `brain-sqlite.py sync`, which rebuilds app/brain.db for the configured mode.
brain-db:
	python3 scripts/brain-sqlite.py build

brain-check:
	python3 scripts/brain-sqlite.py check

# Push the compiled brain into Cloudflare D1. Needs features.brain_d1 = true,
# brain.store = "d1", wrangler, and the [[d1_databases]] binding in wrangler.toml.
brain-d1-push: build
	python3 scripts/brain-d1-deploy.py

# Recording ingestion uses the same ordered stages as the source engine.
# Source providers are optional and explicitly configured by the operator.
# An absent recording graph is an error; this target never opts into empty input.
.PHONY: ingest
ingest:
	python3 scripts/fetch-drive-audio.py
	python3 scripts/diarize-transcripts.py
	python3 scripts/gen-analyses.py
	python3 scripts/gen-transcripts.py
	python3 scripts/gen-sessions.py
	python3 scripts/gen-action-items.py
	python3 scripts/gen-specs.py
	python3 scripts/gen-dependencies.py
	python3 scripts/merge-kg.py merge
	python3 scripts/enrich-kg.py
	python3 scripts/graph-refresh.py
	python3 scripts/gen-knowledge-pack.py

# Explicit reviewed operator migrations; never part of build or verify.
# Action/recovery flags select paths from the plan, so explicitly clear KG=.
FILES :=
KG :=
ARGS :=
APPLY :=
.PHONY: migrate-identifiers migrate-kg
migrate-identifiers:
	python3 scripts/migrate-identifiers.py $(FILES) $(ARGS) $(APPLY)

migrate-kg:
	python3 scripts/migrate-kg.py $(KG) $(ARGS)
