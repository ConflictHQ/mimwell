# The brain's portal as one container (#459): the published asset set (_site/)
# from nginx on 8080, /health, and the read-only MCP endpoint at /mcp, which
# nginx proxies to gunicorn on loopback. See README.md.
#
# Build from the brain's root:
#   docker build -f runtime/portal-container/Dockerfile -t <image> .
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS stage
ARG ASTROLIFT_SOURCE_COMMIT
WORKDIR /src
COPY . .
# Validate the optional host identity before staging anything. A non-empty
# value must be a full lowercase SHA; the host, not this image builder, binds
# it to the immutable source URL and saved deployment commit.
RUN PYTHONDONTWRITEBYTECODE=1 python3 scripts/write_source_receipt.py \
      --validate-source-commit "$ASTROLIFT_SOURCE_COMMIT" \
 && apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf .git \
 && git init -q \
 && git add -A \
 && PYTHONDONTWRITEBYTECODE=1 python3 scripts/build-portal-site.py \
 && mkdir -p /tmp/mimwell-source-attestation \
 && PYTHONDONTWRITEBYTECODE=1 python3 scripts/write_source_receipt.py \
      "$ASTROLIFT_SOURCE_COMMIT" _site/app/brain.json \
      /tmp/mimwell-source-attestation/source-receipt.json \
      --artifact-root /src/_site \
      --artifact-output /tmp/mimwell-source-attestation/source-artifacts.json

FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/brain/scripts BRAIN_ROOT=/srv/brain
RUN apt-get update && apt-get install -y --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
COPY runtime/portal-container/requirements.lock /opt/brain/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/brain/requirements.lock
COPY --from=stage /src/scripts /opt/brain/scripts
COPY --from=stage /src/schemas /opt/brain/schemas
COPY --from=stage /src/_site /srv/brain
COPY --from=stage --chown=0:0 /tmp/mimwell-source-attestation/ /opt/brain/private/
COPY runtime/portal-container/nginx.conf runtime/portal-container/gunicorn.conf.py runtime/portal-container/app-gunicorn.conf.py runtime/portal-container/start.sh /opt/brain/portal/
RUN chown root:root /opt/brain/private \
 && chmod 0555 /opt/brain/private \
 && if [ -f /opt/brain/private/source-receipt.json ]; then \
      chown root:root /opt/brain/private/source-receipt.json \
      && chmod 0444 /opt/brain/private/source-receipt.json; \
    fi \
 && if [ -f /opt/brain/private/source-artifacts.json ]; then \
      chown root:root /opt/brain/private/source-artifacts.json \
      && chmod 0444 /opt/brain/private/source-artifacts.json; \
    fi
USER 10001:10001
EXPOSE 8080
CMD ["bash", "/opt/brain/portal/start.sh"]
