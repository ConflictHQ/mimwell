#!/usr/bin/env python3
"""Create a disabled least-privilege brain app, without changing host policy."""
import argparse
import html
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = {'tracker': 'table-and-chart', 'form': 'form-and-record', 'dashboard': 'dashboard', 'viewer': None}


def scaffold(root, app_id, template):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', app_id):
        raise ValueError('app-id: use a lowercase letter followed by letters, digits or hyphens')
    if template not in TEMPLATES:
        raise ValueError('app-template: choose tracker, form, dashboard or viewer')
    apps = root / 'apps'
    if apps.is_symlink():
        raise ValueError('app-path: apps directory cannot be a symlink')
    destination = apps / app_id
    if destination.exists() or destination.is_symlink():
        raise ValueError('app-exists: refusing to overwrite ' + str(destination))
    apps.mkdir(parents=True, exist_ok=True)
    title = app_id.replace('-', ' ').title()
    manifest = {'id': app_id, 'slug': app_id, 'name': title, 'title': title, 'version': '0.1.0',
                'enabled': False, 'entry': 'index.html', 'stack': 'static', 'runtime': 'brain@1.0.0',
                'template': TEMPLATES[template], 'grant': {'principal': 'app.' + app_id, 'read': [], 'owned': {}, 'elsewhere': 'propose'},
                'pollSeconds': 30, 'budgets': {'bundleBytes': 262144, 'requestsPerMinute': 20},
                'smoke': 'smoke.cjs', 'changelog': [{'version': '0.1.0', 'note': 'Initial disabled app; owner enrollment required.'}]}
    with tempfile.TemporaryDirectory(prefix='brain-app-') as temporary:
        stage = Path(temporary) / app_id
        stage.mkdir()
        (stage / 'app.json').write_text(json.dumps(manifest, indent=2) + '\n')
        for source in (ROOT / 'scripts/app-templates').iterdir():
            text = source.read_text().replace('__TITLE__', html.escape(title)).replace('__MODE__', template).replace('__POLL__', str(manifest['pollSeconds'])).replace('__RATE__', str(manifest['budgets']['requestsPerMinute']))
            (stage / source.name).write_text(text)
        from brain_apps import check_app
        check_app(stage, None, '2026-01-01T00:00:00Z', allow_draft=True)
        shutil.copytree(stage, destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--id', required=True)
    parser.add_argument('--template', choices=TEMPLATES, default='viewer')
    args = parser.parse_args()
    try:
        target = scaffold(args.root, args.id, args.template)
    except (ValueError, OSError) as exc:
        parser.exit(1, str(exc) + '\n')
    print(f'Created disabled draft {target}. Run node {target}/smoke.cjs; review enrollment before enabling.')


if __name__ == '__main__':
    main()
