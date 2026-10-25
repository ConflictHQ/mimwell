"""Reviewed static app bundles, sharing the native app grant contract."""
from pathlib import Path
import json
import re
import os
import hashlib
import stat
from html.parser import HTMLParser

from jsonschema import Draft202012Validator
from app_backend import validate_grant
from knowledge_policy import fingerprint, local_path, timestamp
from knowledge_store import Contract

ROOT = Path(__file__).resolve().parents[1]
MAX_APP_FILES = 10_000
MAX_APP_DEPTH = 32
MAX_APP_BUNDLE_BYTES = 64 * 1024 * 1024


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def snapshot_bundle(bundle_root, app_id, *, expected_root_identity=None, expected_apps_identity=None):
    """Read one installed bundle through pinned no-follow directory handles."""
    if not isinstance(app_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", app_id):
        raise ValueError("app-publish: invalid app identity")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("app-publish: safe bundle snapshot is unsupported")
    max_entries = int(os.environ.get("BRAIN_APPS_MAX_FILES", MAX_APP_FILES))
    max_bytes = int(os.environ.get("BRAIN_APPS_MAX_BUNDLE_BYTES", MAX_APP_BUNDLE_BYTES))
    if not 1 <= max_entries <= MAX_APP_FILES or not 1 <= max_bytes <= MAX_APP_BUNDLE_BYTES:
        raise ValueError("app-publish: invalid bundle capacity")
    root_path = Path(bundle_root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root_path, flags)
    apps_fd = app_fd = None
    files, entries = {}, {}
    total = 0
    entry_count = 0

    def directory_info(info, expected_mode):
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o777 == expected_mode
                and not info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH))

    def walk(directory_fd, prefix, depth):
        nonlocal total, entry_count
        names = []
        with os.scandir(directory_fd) as children:
            for child in children:
                entry_count += 1
                if entry_count > max_entries:
                    raise ValueError("app-budget: bundle exceeds host capacity")
                if depth >= MAX_APP_DEPTH:
                    raise ValueError("app-budget: bundle exceeds host depth limit")
                names.append(child.name)
        for name in sorted(names):
            relative = f"{prefix}/{name}" if prefix else name
            try:
                if local_path(relative).as_posix() != relative:
                    raise ValueError("app-publish: noncanonical bundle path")
            except (TypeError, ValueError) as exc:
                raise ValueError("app-publish: invalid bundle path") from exc
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                if not directory_info(before, 0o755):
                    raise ValueError("app-publish: unsafe bundle directory")
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if _file_identity(opened) != _file_identity(before):
                        raise ValueError("app-publish: bundle changed during snapshot")
                    walk(child_fd, relative, depth + 1)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (_file_identity(os.fstat(child_fd)) != _file_identity(opened)
                            or _file_identity(after) != _file_identity(opened)):
                        raise ValueError("app-publish: bundle changed during snapshot")
                finally:
                    os.close(child_fd)
                continue
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1
                    or before.st_mode & 0o777 not in (0o644, 0o755)
                    or before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)):
                raise ValueError("app-publish: unsafe bundle file")
            if before.st_size > max_bytes - total:
                raise ValueError("app-budget: bundle exceeds host capacity")
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                opened = os.fstat(file_fd)
                if _file_identity(opened) != _file_identity(before):
                    raise ValueError("app-publish: bundle changed during snapshot")
                chunks, remaining = [], before.st_size
                while remaining:
                    chunk = os.read(file_fd, min(64 * 1024, remaining + 1))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("app-publish: bundle file grew during snapshot")
                raw = b"".join(chunks)
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (len(raw) != before.st_size or _file_identity(os.fstat(file_fd)) != _file_identity(opened)
                        or _file_identity(after) != _file_identity(opened)):
                    raise ValueError("app-publish: bundle changed during snapshot")
            finally:
                os.close(file_fd)
            files[relative] = raw
            entries[relative] = {"executable": bool(before.st_mode & 0o111)}
            total += len(raw)

    try:
        root_info = os.fstat(root_fd)
        root_identity = (root_info.st_dev, root_info.st_ino, root_info.st_mode, root_info.st_uid, root_info.st_nlink)
        if (not directory_info(root_info, 0o700)
                or (expected_root_identity is not None and root_identity != expected_root_identity)):
            raise ValueError("app-publish: unsafe private bundle root")
        apps_fd = os.open("apps", flags, dir_fd=root_fd)
        apps_info = os.fstat(apps_fd)
        apps_identity = (apps_info.st_dev, apps_info.st_ino, apps_info.st_mode, apps_info.st_uid, apps_info.st_nlink)
        if (not directory_info(apps_info, 0o700)
                or (expected_apps_identity is not None and apps_identity != expected_apps_identity)):
            raise ValueError("app-publish: unsafe private app directory")
        app_fd = os.open(app_id, flags, dir_fd=apps_fd)
        app_info = os.fstat(app_fd)
        app_name = os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False)
        if (not directory_info(app_info, 0o755)
                or _file_identity(app_info) != _file_identity(app_name)):
            raise ValueError("app-publish: unsafe installed app directory")
        walk(app_fd, "", 0)
        if (_file_identity(os.fstat(app_fd)) != _file_identity(app_info)
                or _file_identity(os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False)) != _file_identity(app_info)
                or _file_identity(os.fstat(apps_fd)) != _file_identity(apps_info)
                or _file_identity(os.fstat(root_fd)) != _file_identity(root_info)):
            raise ValueError("app-publish: bundle path changed during snapshot")
    finally:
        if app_fd is not None:
            os.close(app_fd)
        if apps_fd is not None:
            os.close(apps_fd)
        os.close(root_fd)
    return files, entries


def bundle_digest(files, entries):
    rows = [{"path": path, "mode": "100755" if entries[path]["executable"] else "100644",
             "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for path, raw in sorted(files.items())]
    return fingerprint({"format": "brain-app-bundle/v1", "files": rows})


def read_manifest(directory, *, verified_files=None):
    if verified_files is None:
        if directory.is_symlink() or directory.parent.is_symlink():
            raise ValueError('app-path: symlink app directory')
        path = directory / 'app.json'
        if path.is_symlink():
            raise ValueError('app-path: symlink manifest')
        try:
            manifest = json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            raise ValueError('app-manifest: ' + str(exc)) from exc
    else:
        raw = verified_files.get('app.json') if isinstance(verified_files, dict) else None
        if not isinstance(raw, bytes):
            raise ValueError('app-manifest: verified manifest is unavailable')
        try:
            manifest = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('app-manifest: ' + str(exc)) from exc
    schema = json.loads((ROOT / 'schemas/brain-app.schema.json').read_text())
    errors = list(Draft202012Validator(schema).iter_errors(manifest))
    if errors:
        raise ValueError('app-manifest: ' + '; '.join(error.message for error in errors))
    if manifest['slug'] != directory.name or manifest['id'] != manifest['slug']:
        raise ValueError('app-id: directory/id/slug must agree')
    return manifest


def safe_asset(directory, relative, *, verified_files=None):
    path = local_path(relative)
    if any(part.startswith('.') or part == '_internal' for part in path.parts) or path.suffix == '.map':
        raise ValueError('app-publish: private files and source maps are not served')
    if verified_files is not None:
        if path.as_posix() not in verified_files:
            raise ValueError('app-entry: asset missing')
        return directory / path
    current = directory
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('app-publish: symlinks are not served')
    if not current.is_file():
        raise ValueError('app-entry: asset missing')
    return current


class AppHTML(HTMLParser):
    def __init__(self, directory, modules=False, verified_files=None):
        super().__init__()
        self.directory = directory
        self.modules = modules
        self.verified_files = verified_files

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if any(key.lower().startswith('on') for key in values):
            raise ValueError('app-script: inline event handlers are forbidden')
        if tag == 'script' and values.get('type', '').lower() not in ('', 'text/javascript', 'application/javascript', *(('module',) if self.modules else ())):
            raise ValueError('app-script: module and nonclassic script types are unsupported')
        if tag == 'link' and values.get('rel', '').lower() == 'stylesheet':
            source = values.get('href', '')
            if ':' in source or source.startswith('/'):
                raise ValueError('app-style: remote stylesheets are unsupported')
            safe_asset(self.directory, source, verified_files=self.verified_files)
        if tag == 'script' and values.get('src'):
            source = values['src']
            if ':' in source or source.startswith('/'):
                raise ValueError('app-script: remote script outside empty host allowlist')
            if Path(source).suffix != '.js':
                raise ValueError('app-script: scripts require a checked JavaScript extension')
            safe_asset(self.directory, source, verified_files=self.verified_files)


def check_app(directory, contract, now, *, allow_draft=False, verified_files=None):
    manifest = read_manifest(directory, verified_files=verified_files)
    enabled = manifest.get('enabled', True)
    if not enabled and not allow_draft:
        raise ValueError('app-disabled: draft is not installed')
    if manifest['runtime'] not in ('brain@1.0.0', 'brain@1.1.0'):
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
    safe_asset(directory, manifest['entry'], verified_files=verified_files)
    safe_asset(directory, manifest['smoke'], verified_files=verified_files)
    capacity = int(os.environ.get('BRAIN_APPS_MAX_BUNDLE_BYTES', 64 * 1024 * 1024))
    if manifest['budgets']['bundleBytes'] > capacity:
        raise ValueError('app-budget: declared budget exceeds host capacity')
    catalog = json.loads((ROOT / 'scripts/app-vendor/libraries.json').read_text())
    libraries = {path: digest for item in catalog for path, digest in item['files'].items()}
    total = 0
    count = 0
    if verified_files is None:
        candidates = ((path.relative_to(directory).as_posix(), path) for path in directory.rglob('*'))
    else:
        if not isinstance(verified_files, dict):
            raise ValueError('app-publish: verified file inventory is malformed')
        candidates = iter(sorted(verified_files.items()))
    for relative, item in candidates:
        if not isinstance(relative, str):
            raise ValueError('app-publish: verified file inventory is malformed')
        try:
            normalized = local_path(relative).as_posix()
        except ValueError as exc:
            raise ValueError('app-publish: invalid bundle path') from exc
        if normalized != relative:
            raise ValueError('app-publish: noncanonical bundle path')
        if verified_files is None:
            path = item
            if path.is_symlink():
                raise ValueError('app-publish: symlink in bundle')
            if not path.is_file():
                continue
            count += 1
            if count > int(os.environ.get('BRAIN_APPS_MAX_FILES', 10000)):
                raise ValueError('app-budget: bundle exceeds host file capacity')
            safe_asset(directory, relative)
            if path.stat().st_size > manifest['budgets']['bundleBytes'] - total:
                raise ValueError('app-budget: bundle exceeds declared size budget')
            raw = path.read_bytes()
        else:
            if not isinstance(item, bytes):
                raise ValueError('app-publish: verified file inventory is malformed')
            raw = item
            count += 1
            if count > int(os.environ.get('BRAIN_APPS_MAX_FILES', 10000)):
                raise ValueError('app-budget: bundle exceeds host file capacity')
            safe_asset(directory, relative, verified_files=verified_files)
        total += len(raw)
        if total > manifest['budgets']['bundleBytes']:
            raise ValueError('app-budget: bundle exceeds declared size budget')
        if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk-proj-|AKIA)[A-Za-z0-9]{12,}', raw):
            raise ValueError('app-publish: credential material in bundle')
        bundled = libraries.get(relative) == hashlib.sha256(raw).hexdigest()
        suffix = Path(relative).suffix
        if not bundled and suffix in ('.html', '.js', '.mjs', '.json', '.css'):
            text = raw.decode('utf-8')
            if suffix in ('.html', '.js', '.mjs'):
                if re.search(r'\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write)\b', text):
                    raise ValueError('app-render: HTML string sinks are forbidden; use textContent')
                if re.search(r'(?:import\s*(?:\(|.*?from)|require\s*\()\s*[\"\'](?:https?:|//)', text):
                    raise ValueError('app-script: remote module outside host allowlist')
            if suffix == '.html':
                AppHTML(directory, modules=manifest['runtime'] == 'brain@1.1.0',
                        verified_files=verified_files).feed(text)
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
