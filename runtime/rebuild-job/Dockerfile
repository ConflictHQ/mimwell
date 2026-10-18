# A one-off worker, separate from the serving portal. Mount a trusted standalone
# checkout read-only at /source and an operator-private output volume at /work.
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
RUN apt-get update && apt-get install -y --no-install-recommends git make && rm -rf /var/lib/apt/lists/*
# Reuse the existing hashed base dependency lock. Source-specific gws/provider
# clients are deliberately provisioned by the operator in a derived worker.
COPY runtime/portal-container/requirements.lock /opt/mimwell/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/mimwell/requirements.lock
COPY scripts /opt/mimwell/scripts
COPY schemas /opt/mimwell/schemas
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/mimwell/scripts
WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python3", "/opt/mimwell/scripts/brain-rebuild.py"]
