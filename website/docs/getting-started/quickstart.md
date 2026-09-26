# Quick start

This walks through adding your first document, rebuilding the brain and
previewing the portal. It assumes you finished [Installation](installation.md).

## 1. Name your brain

Open `client.config.json` and set the name your readers will see:

```json
{
  "client": {
    "name": "Acme Handbook",
    "shortName": "ACME",
    "slug": "acme-handbook"
  }
}
```

Keep the rest of the file as it is for now. [Configuration](../configuration.md)
covers the other settings.

## 2. Add a document

Documents live under `knowledge/docs/`. Any Markdown file there is picked up,
including files in subfolders:

```sh
cat > knowledge/docs/welcome.md <<'EOF'
---
title: Welcome
---
# Welcome

Our first decision: we keep what we learn in one place.
EOF
```

## 3. Build

```sh
make build
```

The build compiles your sources into the generated files under `app/`, such as
the search pack (`app/knowledge-pack.json`), the document manifest and the
brain graph (`app/brain.json`).

!!! note "Edit inputs, not outputs"
    Everything the build writes is a projection of your sources. Change the
    documents and records, then rebuild. Hand edits to generated files are
    overwritten on the next build.

## 4. Preview

```sh
npm run dev
```

This runs `wrangler dev` and serves the portal locally, by default at
`http://localhost:8787`. Your document shows up in search and in the library.

The chat agent needs an `ANTHROPIC_API_KEY`. For local use, put it in a
`.dev.vars` file next to `wrangler.toml` (and keep that file out of Git):

```sh
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .dev.vars
```

## 5. Run the checks

```sh
make verify
```

Run this before you commit. It rebuilds, runs the tests and validates the
generated artifacts.

## Next steps

- Learn how the pieces fit in [Concepts](../concepts.md).
- Brand the portal and scope access in [Configuration](../configuration.md).
- Put it online in [Deploying](../deploying.md).
