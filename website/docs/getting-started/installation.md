# Installation

Mimwell is a repository you clone and make your own. There is no package to
install into another project: the repository is the brain.

## Requirements

| Tool | Version | Used for |
|---|---|---|
| Python | 3.14 | The build scripts and tests |
| Node.js | 22 | The Worker's dependencies |
| Wrangler | current | Local preview and deploys to Cloudflare Workers |

Install Wrangler globally if you don't have it:

```sh
npm install -g wrangler
```

## Get the code

```sh
git clone https://github.com/ConflictHQ/mimwell.git my-brain
cd my-brain
```

## Install dependencies

A virtual environment keeps the Python packages out of your system Python:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
npm ci
```

`requirements.txt` holds the few packages the build needs, including
`jsonschema` and `PyYAML`. `npm ci` installs the Worker's dependencies.

## Check the install

```sh
make verify
```

This builds the empty brain, runs the smoke tests and validates every generated
artifact against its schema. It ends with a line like:

```text
validate-schemas: 19 artifact(s) checked, 0 failed.
```

Next: [Quick start](quickstart.md).
