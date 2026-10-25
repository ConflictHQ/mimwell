"""Host-verified (user, app) credentials and bounded Studio-compatible routes."""
from http import HTTPStatus
import hashlib
import hmac
import json
from pathlib import Path
import os
import re
import stat
from urllib.parse import parse_qs, unquote

from app_backend import AppBackend, AppConflict, AppDenied
from brain_apps import bundle_digest, check_app, read_manifest, snapshot_bundle
from context_bundle import encode
from context_host import decode, read_json, read_pinned
from context_http import ContextEndpoint, _Refusal
from knowledge_operations import private_path
from knowledge_policy import PolicyError, local_path
from knowledge_store import StoreError, authority_class


class AppApplication:
    def __init__(self, *, root, host_config, authority, credentials, clock=None,
                 operations_root=None, bundle_root=None, browser_proxy_prefix=None,
                 publication_registry=None, host_brain_id=None, host_environment_id=None):
        self.root, self.host_config, self.authority = Path(root), host_config, authority
        self.operations_root = Path(operations_root) if operations_root is not None else self.root
        self.bundle_root = Path(bundle_root) if bundle_root is not None else self.root
        self.browser_proxy_prefix = self._proxy_prefix(browser_proxy_prefix)
        if self.browser_proxy_prefix is not None and bundle_root is None:
            raise ValueError('Browser proxy presentation requires a private app bundle root')
        self.publication_registry = publication_registry
        self.host_brain_id = self._guid(host_brain_id) if self.browser_proxy_prefix is not None else None
        self.host_environment_id = self._guid(host_environment_id) if self.browser_proxy_prefix is not None else None
        if self.browser_proxy_prefix is not None:
            try:
                registry_parts = local_path(publication_registry).parts
            except (PolicyError, TypeError):
                raise ValueError('Browser proxy presentation requires a private publication registry') from None
            if len(registry_parts) < 2 or registry_parts[0] != '_internal':
                raise ValueError('Browser proxy presentation requires a private publication registry')
        if bundle_root is not None:
            self._validate_roots()
            self._root_pins = self._root_identities() if self.browser_proxy_prefix is not None else None
        else:
            self._root_pins = None
        self.credentials = credentials
        # Reuse the existing bearer authentication, constant-time digest checks,
        # expiry validation and operator-owned credential reload contract.
        self.auth = ContextEndpoint(root=root, host_config=host_config,
                                    credentials=self._credentials, clock=clock)

    @staticmethod
    def _proxy_prefix(value):
        if value is None or value == '':
            return None
        if value != '/api/native-brain':
            raise ValueError('Invalid same-origin app proxy prefix; native browser route is fixed')
        return value

    @staticmethod
    def _guid(value):
        if not isinstance(value, str) or not re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value):
            raise ValueError('Native publication requires canonical Astro GUID pins')
        return value

    @staticmethod
    def _root_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)

    @staticmethod
    def _private_root(value, label):
        path = Path(value)
        if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError(label + ' must be an absolute canonical directory')
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError(label + ' must be a private operator-owned directory')
        return path

    @staticmethod
    def _overlaps(left, right):
        return left == right or left in right.parents or right in left.parents

    def _validate_roots(self):
        self.bundle_root = self._private_root(self.bundle_root, 'App bundle root')
        self.operations_root = self._private_root(self.operations_root, 'Operations root')
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError('Published root must be a real directory')
        published = self.root.resolve(strict=True)
        if (self._overlaps(self.bundle_root, published)
                or self._overlaps(self.bundle_root, self.operations_root)
                or self._overlaps(self.operations_root, published)):
            raise ValueError('Published, operations and app bundle roots must be separate')
        apps = self.bundle_root / 'apps'
        if apps.is_symlink() or not apps.is_dir():
            raise ValueError('Private app bundle root must contain a real apps directory')
        info = apps.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError('Private app bundle directory must be operator-owned')

    def _root_identities(self):
        return tuple(self._root_identity(path.lstat()) for path in (
            self.root, self.operations_root, self.bundle_root, self.bundle_root / 'apps'))

    def _revalidate_roots(self):
        try:
            self._validate_roots()
            if self._root_identities() != self._root_pins:
                raise _Refusal(503)
        except (OSError, ValueError, StoreError):
            raise _Refusal(503) from None

    @staticmethod
    def _publication_digest(descriptor):
        raw = json.dumps(descriptor, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _file_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _read_publications(self):
        try:
            path = private_path(self.operations_root, self.publication_registry)
            before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1 or before.st_mode & 0o777 != 0o600
                    or before.st_size > 256 * 1024):
                raise ValueError('unsafe publication registry')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                opened = os.fstat(fd)
                if self._file_identity(opened) != self._file_identity(before):
                    raise ValueError('publication registry changed')
                chunks, remaining = [], 256 * 1024 + 1
                while remaining:
                    chunk = os.read(fd, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b''.join(chunks)
                after = os.fstat(fd)
                named = path.lstat()
                if (len(raw) > 256 * 1024 or self._file_identity(after) != self._file_identity(opened)
                        or self._file_identity(named) != self._file_identity(opened)):
                    raise ValueError('publication registry changed')
            finally:
                os.close(fd)
            document = decode(raw)
            if (not isinstance(document, dict) or set(document) != {'format', 'publications'}
                    or document['format'] != 'brain-native-app-publications/v1'
                    or not isinstance(document['publications'], dict)
                    or len(document['publications']) > 256):
                raise ValueError('invalid publication registry')
            return document['publications']
        except Exception:
            raise _Refusal(503) from None

    def _publication(self, environ, *, app, store, now):
        if self.browser_proxy_prefix is None:
            return None
        self._revalidate_roots()
        context = environ.get('HTTP_X_BRAIN_APP_CONTEXT')
        route = environ.get('HTTP_X_BRAIN_APP_PROXY_ROUTE')
        if (not isinstance(context, str) or not re.fullmatch(r'[0-9a-f]{64}', context)
                or not isinstance(route, str) or not re.fullmatch(r'[0-9a-f]{64}', route)):
            raise _Refusal(404)
        descriptor = self._read_publications().get(app)
        required = {'format', 'brainId', 'environmentId', 'appId', 'bundleSha256',
                    'authorityBindingSha256', 'sourceRevision'}
        if not isinstance(descriptor, dict) or set(descriptor) != required:
            raise _Refusal(503)
        if (descriptor['format'] != 'brain-native-app-publication/v1'
                or descriptor['brainId'] != self.host_brain_id
                or descriptor['environmentId'] != self.host_environment_id
                or descriptor['appId'] != app
                or not isinstance(descriptor['bundleSha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', descriptor['bundleSha256'])
                or not isinstance(descriptor['authorityBindingSha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', descriptor['authorityBindingSha256'])
                or not isinstance(descriptor['sourceRevision'], str)
                or not re.fullmatch(r'[0-9a-f]{40}', descriptor['sourceRevision'])):
            raise _Refusal(503)
        expected_context = self._publication_digest(descriptor)
        if not hmac.compare_digest(context, expected_context):
            raise _Refusal(404)
        binding = store.contract.binding
        if (not isinstance(binding, str) or not re.fullmatch(r'[0-9a-f]{64}', binding)
                or not hmac.compare_digest(descriptor['authorityBindingSha256'], binding)):
            raise _Refusal(503)
        try:
            files, entries = snapshot_bundle(self.bundle_root, app,
                expected_root_identity=self._root_pins[2], expected_apps_identity=self._root_pins[3])
            self._revalidate_roots()
            if not hmac.compare_digest(bundle_digest(files, entries), descriptor['bundleSha256']):
                raise _Refusal(503)
            directory = self._app_directory(app)
            manifest = check_app(directory, store.contract, now, verified_files=files)
        except _Refusal:
            raise
        except Exception:
            raise _Refusal(503) from None
        return {'context': expected_context, 'route': route, 'files': files,
                'entries': entries, 'manifest': manifest, 'directory': directory}

    def _app_directory(self, app):
        if not isinstance(app, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', app):
            raise _Refusal(403)
        return self.bundle_root / 'apps' / app

    def _credentials(self):
        result = []
        for entry in self.credentials():
            if set(entry) != {'sha256', 'actor', 'app', 'expiresAt'} or not isinstance(entry['app'], str):
                raise ValueError('Invalid app credential')
            result.append({key: value for key, value in entry.items() if key != 'app'})
        return result

    def _identity(self, authorization):
        actor, now = self.auth._authenticate(authorization)
        import hashlib
        digest = hashlib.sha256(authorization[7:].encode('ascii')).hexdigest()
        matches = [entry for entry in self.credentials() if entry['sha256'] == digest and entry['actor'] == actor]
        if len(matches) != 1:
            raise _Refusal(401)
        return actor, matches[0]['app'], now

    def _host(self):
        config = read_json(private_path(self.operations_root, self.host_config))
        if set(config) != {'format', 'binding', 'apps', 'bindings', 'recipe'} or config['format'] != 'brain-app-host/v1':
            raise ValueError('Invalid app host')
        return config

    def handle(self, environ):
        path, method = environ.get('PATH_INFO', ''), environ.get('REQUEST_METHOD')
        app_route = path == '/apps' or path.startswith('/apps/')
        if not (app_route or path in ('/brain/record', '/brain/revision', '/brain/context') or path.startswith('/brain/records/')):
            raise _Refusal(404)
        allowed = ('GET',) if app_route else ('GET', 'POST') if path.startswith('/brain/records/') else ('GET', 'PATCH', 'DELETE') if path == '/brain/record' else ('POST',) if path == '/brain/context' else ('GET',)
        if method not in allowed:
            raise _Refusal(405)
        actor, app, now = self._identity(environ.get('HTTP_AUTHORIZATION'))
        host = self._host()
        grant = host['apps'].get(app)
        if grant is None:
            raise _Refusal(403)
        installed = None
        app_directory = None
        publication = None
        store = None
        if isinstance(grant, str):
            if (self.bundle_root / 'apps').is_symlink() or grant != f'apps/{app}/app.json':
                raise _Refusal(503)
            app_directory = self._app_directory(app)
            if self.browser_proxy_prefix is not None:
                store = authority_class(str(self.authority))(self.authority)
                try:
                    if store.contract.binding != host['binding']:
                        raise _Refusal(503)
                    publication = self._publication(environ, app=app, store=store, now=now)
                    installed = publication['manifest']
                except BaseException:
                    store.close()
                    raise
            else:
                installed = read_manifest(app_directory)
            grant = installed['grant']
        elif self.browser_proxy_prefix is not None:
            raise _Refusal(503)
        try:
            query = parse_qs(environ.get('QUERY_STRING', ''), keep_blank_values=True, strict_parsing=True)
            if any(len(values) != 1 for values in query.values()):
                raise _Refusal(400)
            query = {key: values[0] for key, values in query.items()}
            body = None
            if method != 'GET':
                if environ.get('CONTENT_TYPE') != 'application/json' or environ.get('HTTP_TRANSFER_ENCODING'):
                    raise _Refusal(415)
                length = int(environ.get('CONTENT_LENGTH', '-1'))
                if not 0 <= length <= 65536:
                    raise _Refusal(413)
                raw = environ['wsgi.input'].read(length)
                if len(raw) != length:
                    raise _Refusal(400)
                body = decode(raw)
            current_actor, current_app, now = self._identity(environ.get('HTTP_AUTHORIZATION'))
            if (current_actor, current_app) != (actor, app):
                raise _Refusal(401)
        except BaseException:
            if store is not None:
                store.close()
            raise
        if self.browser_proxy_prefix is not None:
            store.close()
            store = None
        if store is None:
            store = authority_class(str(self.authority))(self.authority)
        try:
            if self.browser_proxy_prefix is not None and self._host() != host:
                raise _Refusal(503)
            if store.contract.binding != host['binding']:
                raise _Refusal(503)
            if self.browser_proxy_prefix is not None:
                publication = self._publication(environ, app=app, store=store, now=now)
                installed = publication['manifest']
                grant = installed['grant']
            backend = AppBackend(store, actor=actor, app=app, grant=grant, now=now,
                                 bindings=read_pinned(self.root, host['bindings']), recipe=read_pinned(self.root, host['recipe']))
            if installed is not None:
                check_app(app_directory, store.contract, now,
                          verified_files=publication['files'] if publication is not None else None)
            if app_route:
                if publication is not None and path == '/apps':
                    raise _Refusal(404)
                if installed is None or query or not any(backend._readable(key) for key in grant['read']):
                    raise _Refusal(404)
                if path == '/apps':
                    return 200, encode({key: installed[key] for key in ('id', 'title', 'version', 'grant', 'runtime')}), []
                if path.rstrip('/') != '/apps/' + app:
                    raise _Refusal(404)
                from app_host import shell
                proxy_prefix = None
                if publication is not None:
                    proxy_prefix = (self.browser_proxy_prefix + '/' + publication['context'] + '/'
                                    + publication['route'] + '/' + app)
                    if len(proxy_prefix) > 212:
                        raise _Refusal(503)
                raw = shell(app_directory, installed,
                            None if proxy_prefix is not None else environ['HTTP_AUTHORIZATION'][7:],
                            browser_proxy_prefix=proxy_prefix,
                            verified_files=publication['files'] if publication is not None else None)
                response_headers = [('Content-Type', 'text/html; charset=utf-8'),
                    ('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")]
                if publication is not None:
                    response_headers.append(('X-Brain-App-Context', publication['context']))
                return 200, raw, response_headers
            if path == '/brain/revision':
                if set(query) != {'scope'}:
                    raise _Refusal(400)
                revision = backend.revision(query['scope'])
                etag = '"' + revision + '"'
                if environ.get('HTTP_IF_NONE_MATCH') == etag:
                    headers = [('ETag', etag)]
                    if publication is not None:
                        headers.append(('X-Brain-App-Context', publication['context']))
                    return 304, b'', headers
                headers = [('ETag', etag)]
                if publication is not None:
                    headers.append(('X-Brain-App-Context', publication['context']))
                return 200, encode({'revision': revision}), headers
            if path == '/brain/context':
                if query:
                    raise _Refusal(400)
                result = backend.context(body)
            elif method == 'GET':
                if path == '/brain/record':
                    if set(query) != {'address'}:
                        raise _Refusal(400)
                    result = backend.records(address=query['address'])
                else:
                    if set(query) - {'q', 'offset', 'limit', 'sort'}:
                        raise _Refusal(400)
                    result = backend.records(kind=unquote(path.removeprefix('/brain/records/')),
                        **{key: int(value) if key in ('offset', 'limit') else value for key, value in query.items()})
            else:
                if set(query) - {'address', 'expectedRevision'}:
                    raise _Refusal(400)
                if 'expectedRevision' in query:
                    if 'expectedRevision' in body and body['expectedRevision'] != query['expectedRevision']:
                        raise _Refusal(400)
                    body['expectedRevision'] = query['expectedRevision']
                if path == '/brain/record' and 'address' not in query:
                    raise _Refusal(400)
                result = backend.mutate(body, kind=unquote(path.removeprefix('/brain/records/')) if method == 'POST' else None,
                    address=query.get('address'), key=environ.get('HTTP_IDEMPOTENCY_KEY'), retract=method == 'DELETE')
            raw = encode(result)
            if len(raw) > 4*1024*1024:
                raise _Refusal(413)
            headers = [('X-Brain-App-Context', publication['context'])] if publication is not None else []
            return 200, raw, headers
        finally:
            store.close()

    def __call__(self, environ, start_response):
        try:
            status, raw, headers = self.handle(environ)
        except _Refusal as exc:
            status, raw, headers = exc.status, b'', []
        except AppConflict:
            status, raw, headers = 409, b'', []
        except (AppDenied, PolicyError):
            status, raw, headers = 403, b'', []
        except (ValueError, TypeError, KeyError, StoreError):
            status, raw, headers = 400, b'', []
        except Exception:
            status, raw, headers = 503, b'', []
        if not any(key == 'Content-Type' for key, _ in headers):
            headers.append(('Content-Type', 'application/json'))
        headers += [('Cache-Control', 'private, no-store'),
                    ('Vary', 'Authorization, X-Brain-App-Context, X-Brain-App-Proxy-Route'),
                    ('X-Content-Type-Options', 'nosniff')]
        start_response(f'{status} {HTTPStatus(status).phrase}', headers)
        return [raw]
