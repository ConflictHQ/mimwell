# Deploying

A Mimwell portal is a Cloudflare Worker that serves its own repository as
static assets. `worker.js` handles routing, search, access checks and the chat
agent; everything else is files.

## Before you deploy

1. Build and check the brain: `make verify`.
2. Name the Worker. In `wrangler.toml`, set `name`, usually `<slug>-portal`:

    ```toml
    name = "acme-handbook-portal"
    ```

3. Log in to Cloudflare: `wrangler login`.

## Deploy

```sh
npm run deploy
```

This runs `wrangler deploy`. The first deploy prints the Worker's
`workers.dev` address.

## Secrets

Secrets never go in the repository. Set them on the Worker:

```sh
wrangler secret put ANTHROPIC_API_KEY   # provider "anthropic" (default)
wrangler secret put OPENAI_API_KEY      # provider "openai"
```

Set the key for the provider named in `assistant.provider`. It powers the chat
agent; without it, the rest of the portal still works.

## Your own domain

Add a custom domain route in `wrangler.toml`. The domain's zone must be on
Cloudflare:

```toml
routes = [
  { pattern = "handbook.example.com", custom_domain = true }
]
```

## Private brains

To keep a brain private, put
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
in front of its custom domain. Access signs readers in and passes their
identity to the Worker, which enforces any `access` rules in
`client.config.json`.

!!! warning "Close the workers.dev side door"
    The Worker's default `workers.dev` address serves the same brain with no
    Access in front. When you go live behind Access on a custom domain, turn it
    off in `wrangler.toml`:

    ```toml
    workers_dev = false
    ```

## Updating

Rebuild, verify and deploy again:

```sh
make verify
npm run deploy
```

Because the build is deterministic, a deploy only changes what your sources
changed.
