"""Sandboxed app entry and a narrow parent bridge bound to one app credential."""
import html
from html.parser import HTMLParser
import json

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
    const headers = {'authorization': 'Bearer ' + token};
    if (method !== 'GET') {
      headers['content-type'] = 'application/json';
      headers['idempotency-key'] = String(args.idempotencyKey || '');
    }
    const response = await fetch(path + (query.size ? '?' + query : ''), {
      method, headers, body: method === 'GET' ? undefined : JSON.stringify(body),
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
    def __init__(self, directory):
        super().__init__(convert_charrefs=False)
        self.directory, self.parts, self.skip_script = directory, [], False
        self.deferred = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script' and values.get('type', '').lower() == 'module':
            raise ValueError('App runtime supports classic scripts only')
        if tag == 'script' and 'src' in values:
            text = safe_asset(self.directory, values['src']).read_text()
            attributes = ''.join(' ' + html.escape(key, quote=True) + ('=\"' + html.escape(value, quote=True) + '\"' if value is not None else '') for key, value in attrs if key != 'src')
            script = '<script' + attributes + '>' + text.replace('</script', '<\\/script') + '</script>'
            (self.deferred if 'defer' in values or 'async' in values else self.parts).append(script)
            self.skip_script = True
        elif tag == 'link' and values.get('rel') == 'stylesheet':
            text = safe_asset(self.directory, values.get('href', '')).read_text()
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


def shell(directory, manifest, token):
    if manifest['runtime'] != 'brain@1.0.0':
        raise ValueError('App runtime pin is not installed on this host')
    parser = Entry(directory)
    parser.feed(safe_asset(directory, manifest['entry']).read_text())
    # Frame CSP denies direct networking/navigation to portal APIs. Its only
    # capability is the parent bridge, whose credential is fixed at enrollment.
    entry = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data:; form-action \'none\'">' + FRAME_RUNTIME + ''.join(parser.parts + parser.deferred)
    def quoted(value):
        return json.dumps(value).replace('<', '\\u003c')
    script = BRIDGE.replace('const token = TOKEN;', 'const token = ' + quoted(token) + ';').replace('frame.srcdoc = ENTRY;', 'frame.srcdoc = ' + quoted(entry) + ';')
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>' + html.escape(manifest['title']) + '</title>'
            '<style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style></head><body>'
            '<iframe sandbox="allow-scripts allow-forms" title="' + html.escape(manifest['title'], quote=True) + '"></iframe>'
            '<script>' + script + '</script></body></html>').encode()
