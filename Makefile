.PHONY: build test verify dev

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
	python3 scripts/gen-staleness.py
	python3 scripts/gen-manifest.py

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 -m unittest discover -s tests

verify: build test
	python3 scripts/validate-schemas.py

dev:
	npm run dev
