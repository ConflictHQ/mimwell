// Access binds the user. An exact enrolled app token binds every backend request.
import {accessEmail} from '../access.js';
const headers = {'cache-control': 'private, no-store', 'vary': 'Cf-Access-Authenticated-User-Email, Authorization',
  'x-content-type-options': 'nosniff'};
const refuse = status => new Response(null, {status, headers});
const catalogPage = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Apps</title></head><body><h1>Apps</h1><p role="status">Loading apps…</p><ul></ul><script>
fetch('/apps/catalog').then(response => {if(!response.ok) throw new Error();return response.json();}).then(apps => {
  document.querySelector('[role=status]').textContent = apps.length ? '' : 'No apps available';
  for(const app of apps) {const li=document.createElement('li'), a=document.createElement('a');a.textContent=app.title;a.href='/apps/'+encodeURIComponent(app.id);li.append(a);document.querySelector('ul').append(li);}
}).catch(()=>{document.querySelector('[role=status]').textContent='Apps unavailable';});
</script></body></html>`;

// Only the operator can choose the service origin. Request paths cannot change it.
export function appService(env) {
  if (env.BRAIN_APP_SERVICE?.fetch) return env.BRAIN_APP_SERVICE;
  if (!env.BRAIN_APP_SERVICE_ORIGIN) return null;
  const base = new URL(env.BRAIN_APP_SERVICE_ORIGIN);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if ((base.protocol !== 'https:' && !(base.protocol === 'http:' && local)) ||
      base.username || base.password || base.pathname !== '/' || base.search || base.hash) {
    throw new Error('BRAIN_APP_SERVICE_ORIGIN must be an HTTPS origin (HTTP only on loopback)');
  }
  return {fetch(url, init) {
    const route = new URL(url);
    return fetch(new URL(base.origin + route.pathname + route.search), {...init, redirect: 'error'});
  }};
}

export function withAppBackend(worker) {
  return {async fetch(request, env, ctx) {
    const url = new URL(request.url), appsRoute = url.pathname === '/apps' || url.pathname.startsWith('/apps/');
    if (!appsRoute && !url.pathname.startsWith('/brain/')) return worker.fetch(request, env, ctx);
    if (typeof worker.canRead !== 'function' || !await worker.canRead(request, env)) return refuse(404);
    const email = accessEmail(request);
    if (!email) return refuse(401);
    if ((request.headers.get('origin') && request.headers.get('origin') !== url.origin) ||
        ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site'))) return refuse(403);
    try {
      const installations = JSON.parse(env.BRAIN_APP_INSTALLATIONS || '{}');
      const installed = Object.hasOwn(installations, email) ? installations[email] : {};
      if (!installed || typeof installed !== 'object' || Array.isArray(installed) || Object.keys(installed).length > 32) return refuse(503);
      if (appsRoute && (request.method !== 'GET' || url.search)) return refuse(400);
      if (url.pathname === '/apps') return new Response(catalogPage, {headers: {...headers, 'content-type': 'text/html; charset=utf-8'}});
      const service = appService(env);
      if (!service) return refuse(503);
      if (url.pathname === '/apps/catalog') {
        const entries = await Promise.all(Object.entries(installed).map(async ([id, token]) => {
          if (!/^[a-z][a-z0-9-]{0,63}$/.test(id) || typeof token !== 'string') return null;
          const appRequest = new Request(new URL('/apps/' + id, url), {headers: request.headers});
          if (!await worker.canRead(appRequest, env)) return null;
          const result = await service.fetch('https://brain-app.internal/apps', {
            headers: {authorization: 'Bearer ' + token}, redirect: 'error', signal: AbortSignal.timeout(10000)});
          if (!result.ok) return null;
          const app = await result.json();
          return app.id === id ? {id: app.id, title: app.title, version: app.version} : null;
        }));
        return Response.json(entries.filter(Boolean), {headers});
      }
      let bearer = request.headers.get('authorization');
      if (appsRoute) {
        const match = /^\/apps\/([a-z][a-z0-9-]{0,63})\/?$/.exec(url.pathname);
        if (!match || !Object.hasOwn(installed, match[1]) || typeof installed[match[1]] !== 'string') return refuse(404);
        bearer = 'Bearer ' + installed[match[1]];
      } else {
        if (!bearer?.startsWith('Bearer ')) return refuse(401);
        const credentials = JSON.parse(env.BRAIN_APP_CREDENTIALS || '{}');
        const tokens = Object.hasOwn(credentials, email) && Array.isArray(credentials[email]) ? credentials[email] : [];
        if (![...tokens, ...Object.values(installed)].includes(bearer.slice(7))) return refuse(403);
        for (const [id, token] of Object.entries(installed)) {
          if (token === bearer.slice(7) && !await worker.canRead(new Request(new URL('/apps/' + id, url), {headers: request.headers}), env)) return refuse(404);
        }
      }
      const raw = await request.arrayBuffer();
      if (raw.byteLength > 65536) return refuse(413);
      const forwarded = new Headers({'authorization': bearer});
      for (const key of ['content-type', 'idempotency-key', 'if-none-match']) {
        if (request.headers.has(key)) forwarded.set(key, request.headers.get(key));
      }
      const response = await service.fetch('https://brain-app.internal' + url.pathname + url.search, {
        method: request.method, headers: forwarded, body: request.method === 'GET' ? undefined : raw,
        redirect: 'error', signal: AbortSignal.timeout(10000)
      });
      const output = new Headers(headers);
      for (const key of ['content-type', 'content-security-policy', 'etag']) {
        if (response.headers.has(key)) output.set(key, response.headers.get(key));
      }
      return new Response(response.body, {status: response.status, headers: output});
    } catch { return refuse(503); }
  }};
}
