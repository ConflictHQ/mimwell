"""Reviewed static app bundles, sharing the native app grant contract."""
from pathlib import Path
import json
import re
from html.parser import HTMLParser

from jsonschema import Draft202012Validator
from app_backend import validate_grant
from knowledge_policy import local_path, timestamp
from knowledge_store import Contract

ROOT = Path(__file__).resolve().parents[1]


def read_manifest(directory):
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError('app-path: symlink app directory')
    path = directory / 'app.json'
    if path.is_symlink():
        raise ValueError('app-path: symlink manifest')
    try:
        manifest = json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        raise ValueError('app-manifest: ' + str(exc)) from exc
    schema = json.loads((ROOT / 'schemas/brain-app.schema.json').read_text())
    errors = list(Draft202012Validator(schema).iter_errors(manifest))
    if errors:
        raise ValueError('app-manifest: ' + '; '.join(error.message for error in errors))
    if manifest['slug'] != directory.name or manifest['id'] != manifest['slug']:
        raise ValueError('app-id: directory/id/slug must agree')
    return manifest


def safe_asset(directory, relative):
    path = local_path(relative)
    if any(part.startswith('.') or part == '_internal' for part in path.parts) or path.suffix == '.map':
        raise ValueError('app-publish: private files and source maps are not served')
    current = directory
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('app-publish: symlinks are not served')
    if not current.is_file():
        raise ValueError('app-entry: asset missing')
    return current


class AppHTML(HTMLParser):
    def __init__(self, directory):
        super().__init__()
        self.directory = directory

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if any(key.lower().startswith('on') for key in values):
            raise ValueError('app-script: inline event handlers are forbidden')
        if tag == 'script' and values.get('type', '').lower() not in ('', 'text/javascript', 'application/javascript'):
            raise ValueError('app-script: module and nonclassic script types are unsupported')
        if tag == 'link' and values.get('rel', '').lower() == 'stylesheet':
            source = values.get('href', '')
            if ':' in source or source.startswith('/'):
                raise ValueError('app-style: remote stylesheets are unsupported')
            safe_asset(self.directory, source)
        if tag == 'script' and values.get('src'):
            source = values['src']
            if ':' in source or source.startswith('/'):
                raise ValueError('app-script: remote script outside empty host allowlist')
            if Path(source).suffix != '.js':
                raise ValueError('app-script: scripts require a checked JavaScript extension')
            safe_asset(self.directory, source)


def check_app(directory, contract, now, *, allow_draft=False):
    manifest = read_manifest(directory)
    enabled = manifest.get('enabled', True)
    if not enabled and not allow_draft:
        raise ValueError('app-disabled: draft is not installed')
    if manifest['runtime'] != 'brain@1.0.0':
        raise ValueError('app-runtime: runtime pin is not installed on this host')
    grant = manifest['grant']
    if any('*' in key for key in [grant['principal'], *grant['read'], *grant['owned']]):
        raise ValueError('app-grant: wildcard grants are forbidden')
    if any(not key.startswith('app.' + manifest['id'] + '.') or key.endswith('.') for key in grant['owned']):
        raise ValueError('app-namespace: owned collections require app.<id>.<name>')
    if enabled:
        if contract is None:
            raise ValueError('app-recipe: enabled app requires adopted authority')
        try:
            validate_grant(grant, contract, now)
        except ValueError as exc:
            raise ValueError('app-grant: ' + str(exc)) from exc
    elif grant['read'] or grant['owned']:
        raise ValueError('app-draft: unenrolled drafts must have empty grants')
    for key in ('pollSeconds', 'budgets', 'smoke', 'changelog'):
        if key not in manifest:
            raise ValueError('app-standard: missing ' + key)
    if manifest['changelog'][0]['version'] != manifest['version']:
        raise ValueError('app-version: newest changelog must match version')
    if 60 / manifest['pollSeconds'] > manifest['budgets']['requestsPerMinute']:
        raise ValueError('app-rate: polling exceeds declared request budget')
    safe_asset(directory, manifest['entry'])
    safe_asset(directory, manifest['smoke'])
    total = 0
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('app-publish: symlink in bundle')
        if path.is_file():
            safe_asset(directory, path.relative_to(directory).as_posix())
            total += path.stat().st_size
            if total > manifest['budgets']['bundleBytes']:
                raise ValueError('app-budget: bundle exceeds declared size budget')
            raw = path.read_bytes()
            if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk-proj-|AKIA)[A-Za-z0-9]{12,}', raw):
                raise ValueError('app-publish: credential material in bundle')
            if path.suffix in ('.html', '.js', '.mjs', '.json', '.css'):
                text = raw.decode('utf-8')
                if path.suffix in ('.html', '.js', '.mjs'):
                    if re.search(r'\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write)\b', text):
                        raise ValueError('app-render: HTML string sinks are forbidden; use textContent')
                    if re.search(r'(?:import\s*(?:\(|.*?from)|require\s*\()\s*[\"\'](?:https?:|//)', text):
                        raise ValueError('app-script: remote module outside host allowlist')
                if path.suffix == '.html':
                    AppHTML(directory).feed(text)
    if total > manifest['budgets']['bundleBytes']:
        raise ValueError('app-budget: bundle exceeds declared size budget')
    return manifest


def check_all(root, now):
    apps = root / 'apps'
    if apps.is_symlink():
        raise ValueError('app-path: apps directory cannot be a symlink')
    if apps.exists() and any(not path.is_dir() and path.name != 'contract.json' for path in apps.iterdir()):
        raise ValueError('app-path: unexpected file under apps')
    directories = sorted(path for path in apps.iterdir() if path.is_dir()) if apps.exists() else []
    if not directories:
        return []
    timestamp(now)
    contract = None
    if any(read_manifest(directory).get('enabled', True) for directory in directories):
        try:
            bundle = json.loads((apps / 'contract.json').read_text())
            contract = Contract(bundle)
            config = json.loads((root / 'client.config.json').read_text())
        except (ValueError, OSError, KeyError) as exc:
            raise ValueError('app-recipe: adopted authority unavailable: ' + str(exc)) from exc
        if config.get('brain', {}).get('authority', {}).get('binding') != contract.binding:
            raise ValueError('app-recipe: app collections differ from adopted authority')
    return [check_app(directory, contract, now, allow_draft=True) for directory in directories]
