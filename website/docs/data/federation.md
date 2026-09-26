# Federation

Brains can form a hierarchy: a person's brain inside a team's, a project's
inside a company's. Each brain declares where it sits and what it is willing
to share upward. Sharing is **closed by default**: a brain that declares
nothing shares nothing.

## Where a brain sits

`scope` in `client.config.json` places the brain on the scope ladder
(federation, company, domain, project, workspace, person, or agent for an
autonomous node):

```json title="client.config.json (excerpt)"
{
  "scope": {
    "level": "project",
    "id": "checkout",
    "parent": "company:example",
    "peers": []
  }
}
```

Ownership flows down, summaries flow up, and access narrows on the way up.

## What a brain shares

`federation` is the publish-upward contract. `publishes` lists the kind ids a
parent may receive; everything else is withheld.

```json title="client.config.json (excerpt)"
{
  "federation": {
    "publishes": ["doc", "wiki-page"],
    "withholds": [],
    "children": [],
    "enrollments": []
  }
}
```

After `make build`, `app/brain-manifest.json` states the contract under
`policy`:

```json
{
  "policy": {
    "publishes": ["doc", "wiki-page"],
    "withholds": ["action-item", "decision", "memory-note", "person", "..."]
  }
}
```

Every declared kind that is not published appears in `withholds`, so the
manifest always says plainly what stays home. Kinds you list that your
ontology does not declare are ignored.

## Serving across brains

The engine also contains a federation service that answers searches and
context requests across several brains at request time, rechecking each source
brain's own read policy on every call. Running it needs a separate
authenticated host for each realm and operator configuration that this release
does not package or document yet. For now, federation in this release means the
declarations above.
