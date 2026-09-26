"""Host-verified (user, app) credentials and bounded Studio-compatible routes."""
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, unquote

from app_backend import AppBackend, AppConflict, AppDenied
from context_bundle import encode
from context_host import decode, read_json, read_pinned
from context_http import ContextEndpoint, _Refusal
from knowledge_operations import private_path
from knowledge_policy import PolicyError
from knowledge_store import StoreError, authority_class


class AppApplication:
    def __init__(self, *, root, host_config, authority, credentials, clock=None):
        self.root, self.host_config, self.authority = Path(root), host_config, authority
        self.credentials = credentials
        # Reuse the existing bearer authentication, constant-time digest checks,
        # expiry validation and operator-owned credential reload contract.
        self.auth = ContextEndpoint(root=root, host_config=host_config,
                                    credentials=self._credentials, clock=clock)

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
        config = read_json(private_path(self.root, self.host_config))
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
        if isinstance(grant, str):
            if (self.root / 'apps').is_symlink() or grant != f'apps/{app}/app.json':
                raise _Refusal(503)
            from brain_apps import read_manifest
            installed = read_manifest(self.root / 'apps' / app)
            grant = installed['grant']
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
        store = authority_class(str(self.authority))(self.authority)
        try:
            if store.contract.binding != host['binding']:
                raise _Refusal(503)
            backend = AppBackend(store, actor=actor, app=app, grant=grant, now=now,
                                 bindings=read_pinned(self.root, host['bindings']), recipe=read_pinned(self.root, host['recipe']))
            if installed is not None:
                from brain_apps import check_app
                check_app(self.root / 'apps' / app, store.contract, now)
            if app_route:
                if installed is None or query or not any(backend._readable(key) for key in grant['read']):
                    raise _Refusal(404)
                if path == '/apps':
                    return 200, encode({key: installed[key] for key in ('id', 'title', 'version', 'grant', 'runtime')}), []
                if path.rstrip('/') != '/apps/' + app:
                    raise _Refusal(404)
                from app_host import shell
                raw = shell(self.root / 'apps' / app, installed, environ['HTTP_AUTHORIZATION'][7:])
                return 200, raw, [('Content-Type', 'text/html; charset=utf-8'),
                    ('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")]
            if path == '/brain/revision':
                if set(query) != {'scope'}:
                    raise _Refusal(400)
                revision = backend.revision(query['scope'])
                etag = '"' + revision + '"'
                if environ.get('HTTP_IF_NONE_MATCH') == etag:
                    return 304, b'', [('ETag', etag)]
                return 200, encode({'revision': revision}), [('ETag', etag)]
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
            return 200, raw, []
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
                    ('Vary', 'Authorization'), ('X-Content-Type-Options', 'nosniff')]
        start_response(f'{status} {HTTPStatus(status).phrase}', headers)
        return [raw]
