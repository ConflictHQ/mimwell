# The brain's portal as one container (#459): the published asset set (_site/)
# from nginx on 8080, /health, and the read-only MCP endpoint at /mcp, which
# nginx proxies to gunicorn on loopback. See README.md.
#
# Build from the brain's root:
#   docker build -f runtime/portal-container/Dockerfile -t <image> .
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS stage
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The stager publishes tracked files, listed by git. A platform build context
# arrives as a source archive and a local one may hold a worktree's .git file,
# so the context is indexed afresh: .gitignore keeps local files out of the
# index, .assetsignore keeps internal ones out of _site/.
RUN rm -rf .git \
 && git init -q \
 && git add -A \
 && PYTHONDONTWRITEBYTECODE=1 python3 scripts/build-portal-site.py

FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/brain/scripts BRAIN_ROOT=/srv/brain
RUN apt-get update && apt-get install -y --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
COPY runtime/portal-container/requirements.lock /opt/brain/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/brain/requirements.lock
COPY --from=stage /src/scripts /opt/brain/scripts
COPY --from=stage /src/schemas /opt/brain/schemas
COPY --from=stage /src/_site /srv/brain
COPY runtime/portal-container/nginx.conf runtime/portal-container/gunicorn.conf.py runtime/portal-container/start.sh /opt/brain/portal/
USER 10001:10001
EXPOSE 8080
CMD ["bash", "/opt/brain/portal/start.sh"]
