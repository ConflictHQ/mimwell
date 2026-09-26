# Configuration

One file configures a brain: `client.config.json` at the repository root. It's
validated against `schemas/client.config.schema.json` on every `make verify`,
so a typo fails the check instead of reaching readers.

## Identity

```json
{
  "client": {
    "name": "Acme Handbook",
    "shortName": "ACME",
    "slug": "acme-handbook",
    "engagement": "Team handbook"
  }
}
```

- `name` is shown to readers. `shortName` is used where space is tight.
- `slug` names the brain in URLs and tooling. The Worker name in
  `wrangler.toml` usually follows it, as `<slug>-portal`.

## Branding

Everything visual lives under `branding`:

```json
{
  "branding": {
    "portalTitle": "Acme Handbook",
    "owner": {
      "name": "Acme",
      "mark": "/assets/brand/acme-light.svg",
      "markDark": "/assets/brand/acme-dark.svg"
    },
    "heroMark": "/assets/brand/acme-light.svg",
    "heroMarkDark": "/assets/brand/acme-dark.svg",
    "heroMarkWidth": 96,
    "colors": {
      "primary": "#3B6FD4",
      "link": "#4A86E8",
      "accent": "#E0A030",
      "bg": "#0F1117",
      "text": "#E6E8EE"
    },
    "fonts": {
      "heading": "'Fraunces', Georgia, serif",
      "body": "'Inter', system-ui, sans-serif",
      "mono": "'JetBrains Mono', monospace"
    },
    "greeting": "Ask about anything in the handbook.",
    "inputPlaceholder": "Ask the handbook…"
  }
}
```

- **`owner`** is the party running the brain, shown in the topbar and page
  footers. Give it a `name` and optional `mark` / `markDark` artwork. With no
  mark, the name is shown as a text wordmark. The default is the placeholder
  `ACME`; set `"owner": ""` to drop the owner brand entirely.
- **`heroMark`** and **`heroMarkDark`** set the home page artwork for light and
  dark themes.
- **`colors`** and **`fonts`** override the default Mimwell palette and type.
  The color keys are `primary`, `link`, `accent`, `bg`, `bgDeep`, `surface`,
  `border`, `borderLight`, `text`, `textMuted` and `textFaint`.
- **`greeting`** and **`inputPlaceholder`** set the chat agent's opening text.

Put your artwork under `assets/brand/`. Mimwell's own marks live there too;
point the fields above at your files to replace them.

## Theme

```json
{ "theming": { "default": "dark" } }
```

`light` or `dark`. Readers can switch, and their choice is remembered.

## Portal

```json
{
  "portal": {
    "template": "company",
    "view": { "default": "easy" }
  }
}
```

- `template` picks the home page for the brain's purpose: `auto`,
  `engagement`, `company`, `topic`, `personal`, `wiki`, `catalog`,
  `federation` or `console`.
- `view.default` is `easy` or `advanced`. See
  [Easy and Advanced views](concepts.md#easy-and-advanced-views).

## Profile

```json
{
  "profile": {
    "base": "core",
    "overlays": ["engagement", "data"]
  }
}
```

The profile decides which record kinds the brain composes. The available
overlays are the files in `profiles/`. Add `sensemaking` to turn on the
[sensemaking workbench](guide/sensemaking.md).

## Knowledge sources

```json
{
  "knowledge": {
    "sources": [
      { "path": "knowledge/docs", "recursive": true }
    ]
  }
}
```

`sources` lists the folders the build reads documents from.

## Assistant

```json
{
  "assistant": {
    "model": "claude-sonnet-4-6",
    "maxAgentTurns": 8,
    "identity": "Answer questions using the current portal knowledge and cite the available sources.",
    "audience": "The people authorized to use this brain."
  }
}
```

The agent needs an `ANTHROPIC_API_KEY` secret on the Worker. See
[Deploying](deploying.md#secrets).

## Access

Access control is optional and off by default. It needs the portal served
behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/),
which authenticates readers and tells the Worker who they are.

```json
{
  "access": {
    "owners": ["lead@example.com"],
    "restricted": [
      "knowledge/docs/finance/",
      { "path": "knowledge/docs/hr/**", "owners": ["people@example.com"] }
    ]
  }
}
```

- `owners` can read everything. Use full email addresses.
- `restricted` lists path globs only owners may read. The object form also
  grants that entry to the extra `owners` it names. A rule for a folder covers
  everything beneath it; `*` stays within one path segment and `**` crosses
  segments.
- Rules only narrow. A reader must be allowed by every rule that matches a path.
- The rules are enforced on static files, search results, the graph, the
  agent's answers and the served config. The `access` block itself is never
  sent to a browser.
- It fails closed. If the block can't be parsed, everything is restricted and
  nobody is an owner.
