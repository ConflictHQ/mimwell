# Sensemaking

The sensemaking workbench helps a team reason about a question: the concepts in
play, the observations and evidence behind them, the interpretations people
draw, situational assessments, the probes they run and strategic maps.

These are reviewed judgments, not objective classifications. The workbench
keeps them separate from the brain's factual records.

## Turn it on

Sensemaking is opt-in. Add the `sensemaking` overlay to the profile in
`client.config.json`:

```json
{
  "profile": {
    "base": "core",
    "overlays": ["engagement", "data", "sensemaking"]
  }
}
```

Then rebuild:

```sh
make build
```

The overlay composes the sensemaking record kinds into the brain's schema and
shows the workbench page at `/sensemaking/`. Its records live in
`app/sensemaking.json`.

## Turn it off

Remove `sensemaking` from `profile.overlays` and rebuild.
