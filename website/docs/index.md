---
title: Mimwell
hide:
  - navigation
  - toc
---

<div class="mw-hero" markdown>

<img class="mw-hero-mark--dark" src="assets/images/mimwell-mark-dark.svg" alt="Mimwell mark">
<img class="mw-hero-mark--light" src="assets/images/mimwell-mark-light.svg" alt="Mimwell mark">

<h1 class="mw-wordmark"><img class="mw-hero-mark--dark" src="assets/images/mimwell-wordmark-dark.svg" alt="Mimwell"><img class="mw-hero-mark--light" src="assets/images/mimwell-wordmark-light.svg" alt="Mimwell"></h1>

<p class="mw-tagline">A knowledge brain for people, teams and agents.</p>

[Get started](getting-started/installation.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/ConflictHQ/mimwell){ .md-button }

<p class="mw-runes" aria-hidden="true">ᛗᛁᛗᚹᛖᛚᛚ</p>

</div>

Mimwell is a knowledge brain you run yourself. It compiles your documents,
decisions, plans and records into one graph and search index. A portal serves
that graph to people, and a retrieval agent answers questions from it.

The name comes from Mímir's well, the spring under the world tree whose water
held wisdom and memory. Mimwell does the same job for a team: it keeps what the
team learned somewhere anyone can draw from.

## What you get

- **A compiled brain.** Markdown documents and structured records build into a
  knowledge graph, a search pack and a manifest. The build is deterministic, so
  the same inputs always produce the same outputs.
- **A portal.** A static site served by a Cloudflare Worker, with an Easy view
  for readers and an Advanced view for people who want every record kind, the
  graph and the sources.
- **A retrieval agent.** Chat that answers from the brain's own content and
  cites its sources.
- **Your brand.** Name, colors, fonts and marks come from one config file.
- **Access control.** Optional per-path read scoping behind Cloudflare Access,
  enforced on every page, search result and agent answer. It fails closed.
- **Brain apps.** Small, sandboxed apps that run beside the portal.
- **Sensemaking.** An opt-in workbench for concepts, evidence, assessments and
  strategic maps.

## Where to go next

- [Installation](getting-started/installation.md): what you need on your machine.
- [Quick start](getting-started/quickstart.md): build and preview your first brain.
- [Concepts](concepts.md): how a brain is put together.
- [Configuration](configuration.md): make it yours.
- [Deploying](deploying.md): put it on your own domain.

Mimwell is open source under the [Apache License 2.0](license.md), built by
[CONFLICT](about.md).
