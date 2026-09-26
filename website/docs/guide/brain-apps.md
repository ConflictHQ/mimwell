# Brain apps

Brain apps are small, sandboxed web apps that sit beside a brain: a tracker, a
form, a dashboard or a viewer. Each app declares exactly what it may read and
where it may write, and starts disabled until an owner enrolls it.

## Create an app

```sh
python3 scripts/new-brain-app.py --id handbook-tracker --template tracker
```

Templates are `tracker`, `form`, `dashboard` and `viewer`. The command creates a
disabled draft under `apps/<id>/`:

| File | Purpose |
|---|---|
| `app.json` | The manifest: name, version, grant, budgets, smoke test |
| `index.html`, `app.js`, `shell.css` | The app itself |
| `poll.js` | Revision polling helper |
| `smoke.cjs` | The app's smoke test |

It never changes host policy on its own.

## The manifest

`app.json` carries the app's least-privilege **grant**:

- `read` lists what the app may read.
- `owned` lists the collections the app writes directly.
- `elsewhere: "propose"` means any other change is submitted as a proposal for
  review, not written.

It also sets **budgets** (bundle size, requests per minute) and a polling
interval. New apps start with `"enabled": false`.

## Check and test

```sh
node apps/handbook-tracker/smoke.cjs
python3 scripts/check-brain-apps.py
```

The smoke test exercises the app against fixtures. `check-brain-apps.py`
validates every installed app against its recipe and grant, and reports how
many are enabled and how many are drafts.

## Serving apps

Apps are served by an authenticated app host, separate from the static portal.
Enable an app only after reviewing its grant, then set `"enabled": true`.
