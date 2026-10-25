"""Sandboxed app entry and a narrow parent bridge bound to one app credential."""
import html
from html.parser import HTMLParser
import json
import base64
import mimetypes
from pathlib import Path

from brain_apps import safe_asset


# No token, user or app selector enters the frame. Responses return only to its
# exact WindowProxy; opaque origins alone never authenticate a sender.
FRAME_RUNTIME = '''<script>
(() => {
  let serial = 0;
  const pending = new Map();
  window.addEventListener('message', event => {
    if (event.source !== parent || event.data?.channel !== 'brain-app/v1') return;
    const slot = pending.get(event.data.id);
    if (!slot) return;
    pending.delete(event.data.id);
    clearTimeout(slot.timer);
    event.data.error ? slot.reject(new Error(event.data.error)) : slot.resolve(event.data.result);
  });
  window.brain = Object.freeze({request(operation, args = {}) {
    return new Promise((resolve, reject) => {
      const id = ++serial;
      const timer = setTimeout(() => {pending.delete(id); reject(new Error('Request timed out'));}, 15000);
      pending.set(id, {resolve, reject, timer});
      parent.postMessage({channel: 'brain-app/v1', id, operation, args}, '*');
    });
  }});
})();
</script>'''

BRIDGE = '''
const frame = document.querySelector('iframe');
const token = TOKEN;
const proxyPrefix = PROXY_PREFIX;
frame.srcdoc = ENTRY;
let active = 0;
window.addEventListener('message', async event => {
  if (event.source !== frame.contentWindow || event.data?.channel !== 'brain-app/v1') return;
  const {id, operation, args = {}} = event.data;
  if (!Number.isSafeInteger(id) || active >= 4) return;
  const reply = value => frame.contentWindow.postMessage({channel: 'brain-app/v1', id, ...value}, '*');
  let path, method = 'GET', body;
  const query = new URLSearchParams();
  if (operation === 'records') {
    path = '/brain/records/' + encodeURIComponent(args.kind);
    for (const key of ['q', 'limit', 'offset', 'sort']) if (args[key] !== undefined) query.set(key, args[key]);
  } else if (['record', 'update', 'retract'].includes(operation)) {
    path = '/brain/record'; query.set('address', args.address);
    if (operation !== 'record') {method = operation === 'update' ? 'PATCH' : 'DELETE'; body = args.body;}
  } else if (operation === 'revision') {
    path = '/brain/revision'; query.set('scope', args.scope);
  } else if (operation === 'create') {
    path = '/brain/records/' + encodeURIComponent(args.kind); method = 'POST'; body = args.body;
  } else if (operation === 'context') {
    path = '/brain/context'; method = 'POST'; body = args.body;
  } else {reply({error: 'Unsupported app operation'}); return;}
  active++;
  try {
    const headers = proxyPrefix ? {'x-platform': 'web'} : {'authorization': 'Bearer ' + token};
    if (method !== 'GET') {
      headers['content-type'] = 'application/json';
      headers['idempotency-key'] = String(args.idempotencyKey || '');
    }
    const response = await fetch((proxyPrefix || '') + path + (query.size ? '?' + query : ''), {
      method, headers, body: method === 'GET' ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      redirect: proxyPrefix ? 'error' : 'follow',
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error(response.status === 409 ? 'Changed since you opened' :
      response.status === 403 ? 'Restricted' : 'App request unavailable');
    reply({result: await response.json()});
  } catch (error) {reply({error: error.message});}
  finally {active--;}
});
'''


class Entry(HTMLParser):
    """Inline local scripts/styles so opaque frames need no ambient cookies."""
    def __init__(self, directory, verified_files=None):
        super().__init__(convert_charrefs=False)
        self.directory, self.verified_files = directory, verified_files
        self.parts, self.skip_script = [], False
        self.deferred = []

    def _text(self, relative):
        path = safe_asset(self.directory, relative, verified_files=self.verified_files)
        if self.verified_files is not None:
            return self.verified_files[relative].decode('utf-8')
        return path.read_text()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script' and values.get('type', '').lower() == 'module':
            raise ValueError('App runtime supports classic scripts only')
        if tag == 'script' and 'src' in values:
            text = self._text(values['src'])
            attributes = ''.join(' ' + html.escape(key, quote=True) + ('=\"' + html.escape(value, quote=True) + '\"' if value is not None else '') for key, value in attrs if key != 'src')
            script = '<script' + attributes + '>' + text.replace('</script', '<\\/script') + '</script>'
            (self.deferred if 'defer' in values or 'async' in values else self.parts).append(script)
            self.skip_script = True
        elif tag == 'link' and values.get('rel') == 'stylesheet':
            text = self._text(values.get('href', ''))
            self.parts.append('<style>' + text.replace('</style', '<\\/style') + '</style>')
        else:
            self.parts.append(self.get_starttag_text())

    def handle_endtag(self, tag):
        if tag == 'script' and self.skip_script:
            self.skip_script = False
        else:
            self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        if not self.skip_script:
            self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        self.parts.append('&#' + name + ';')

    def handle_decl(self, decl):
        self.parts.append('<!' + decl + '>')


def _proxy_prefix(value):
    import re
    if value is None:
        return None
    if (not isinstance(value, str) or len(value) > 212
            or not re.fullmatch(r'/api/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', value)):
        raise ValueError('Invalid same-origin app proxy prefix')
    return value


def _bridge_script(token, proxy_prefix):
    if proxy_prefix is None:
        if not isinstance(token, str) or not token:
            raise ValueError('Bearer app presentation requires its existing credential')
        token_value = json.dumps(token).replace('<', '\\u003c')
        prefix_value = 'null'
    else:
        token_value = 'null'
        prefix_value = json.dumps(proxy_prefix).replace('<', '\\u003c')
    return (BRIDGE.replace('const token = TOKEN;', 'const token = ' + token_value + ';')
            .replace('const proxyPrefix = PROXY_PREFIX;', 'const proxyPrefix = ' + prefix_value + ';'))


def shell(directory, manifest, token, *, browser_proxy_prefix=None, verified_files=None):
    browser_proxy_prefix = _proxy_prefix(browser_proxy_prefix)
    if manifest['runtime'] == 'brain@1.1.0':
        return portable_shell(directory, manifest, token, browser_proxy_prefix=browser_proxy_prefix,
                              verified_files=verified_files)
    if manifest['runtime'] != 'brain@1.0.0':
        raise ValueError('App runtime pin is not installed on this host')
    parser = Entry(directory, verified_files=verified_files)
    parser.feed(parser._text(manifest['entry']))
    # Frame CSP denies direct networking/navigation to portal APIs. Its only
    # capability is either the legacy credential-bound bridge or the fixed
    # same-origin proxy selected by the operator.
    entry = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data:; form-action \'none\'">' + FRAME_RUNTIME + ''.join(parser.parts + parser.deferred)
    def quoted(value):
        return json.dumps(value).replace('<', '\\u003c')
    script = _bridge_script(token, browser_proxy_prefix).replace('frame.srcdoc = ENTRY;', 'frame.srcdoc = ' + quoted(entry) + ';')
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>' + html.escape(manifest['title']) + '</title>'
            '<style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style></head><body>'
            '<iframe sandbox="allow-scripts allow-forms" title="' + html.escape(manifest['title'], quote=True) + '"></iframe>'
            '<script>' + script + '</script></body></html>').encode()


class PortableEntry(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            values = dict(attrs)
            kind = 'module' if values.get('type') == 'module' else 'classic'
            self.parts.append('<script type="application/x-brain-script" data-brain-script="' + kind + '"' +
                              (' data-brain-src="' + html.escape(values['src'], quote=True) + '"' if values.get('src') else '') + '>')
        else:
            self.parts.append(self.get_starttag_text())

    def handle_endtag(self, tag):
        self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        self.parts.append('&#' + name + ';')


def portable_shell(directory, manifest, token, *, browser_proxy_prefix=None, verified_files=None):
    browser_proxy_prefix = _proxy_prefix(browser_proxy_prefix)
    def quoted(value):
        return json.dumps(value).replace('<', '\\u003c')
    assets = {}
    if verified_files is None:
        candidates = ((path.relative_to(directory).as_posix(), path) for path in directory.rglob('*')
                      if path.is_file())
        for name, path in candidates:
            safe_asset(directory, name)
            raw = path.read_bytes()
            suffix = Path(name).suffix
            mime = {'.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm'}.get(suffix)
            assets[name] = {'type': mime or mimetypes.guess_type(name)[0] or 'application/octet-stream',
                            'data': base64.b64encode(raw).decode()}
    else:
        for name, raw in sorted(verified_files.items()):
            safe_asset(directory, name, verified_files=verified_files)
            suffix = Path(name).suffix
            mime = {'.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm'}.get(suffix)
            assets[name] = {'type': mime or mimetypes.guess_type(name)[0] or 'application/octet-stream',
                            'data': base64.b64encode(raw).decode()}
    scripts = Path(__file__).parent
    lexer = base64.b64encode((scripts / 'app-vendor/es-module-lexer.js').read_bytes()).decode()
    loader = (scripts / 'app_bundle.mjs').read_text().replace('./app-vendor/es-module-lexer.js', 'data:text/javascript;base64,' + lexer)
    parser = PortableEntry()
    if verified_files is None:
        entry = safe_asset(directory, manifest['entry']).read_text()
    else:
        entry = verified_files[manifest['entry']].decode('utf-8')
    parser.feed(entry)
    policy = "default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval' blob: data:; style-src 'unsafe-inline' blob:; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src blob: data:; base-uri 'none'; form-action 'none'"
    entry = '<meta http-equiv="Content-Security-Policy" content="' + html.escape(policy, quote=True) + '">' + FRAME_RUNTIME
    entry += ''.join(parser.parts)
    entry += '<script type="application/json" id="brain-app-assets">' + quoted(assets) + '</script>'
    entry += '<script type="module">' + loader.replace('</script', '<\\/script') + '</script>'
    script = _bridge_script(token, browser_proxy_prefix).replace('frame.srcdoc = ENTRY;', 'frame.srcdoc = ' + quoted(entry) + ';')
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>' + html.escape(manifest['title']) + '</title>'
            '<style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style></head><body>'
            '<iframe sandbox="allow-scripts allow-forms" title="' + html.escape(manifest['title'], quote=True) + '"></iframe>'
            '<script>' + script + '</script></body></html>').encode()
