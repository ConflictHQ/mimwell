// Explicit Worker extension for a separately enrolled context inspection service.
// Like worker.js, this requires Cloudflare Access on EVERY served hostname.
// The upstream authenticated email selects a private, exact per-user credential;
// no shared fallback, caller-supplied bearer or browser-selected backend exists.
import {accessEmail} from '../access.js';

async function bounded(stream, limit, signal) {
  if (signal.aborted) throw new Error('Context inspection deadline');
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(), chunks = [];
  let size = 0, done = false;
  const cancel = () => { reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, {once: true});
  try {
    for (;;) {
      const part = await reader.read();
      if (signal.aborted) throw new Error('Context inspection deadline');
      if (part.done) { done = true; break; }
      size += part.value.byteLength;
      if (size > limit) throw new Error('Context inspection byte limit');
      chunks.push(part.value);
    }
    const result = new Uint8Array(size);
    let offset = 0;
    for (const part of chunks) { result.set(part, offset); offset += part.byteLength; }
    return result;
  } finally {
    signal.removeEventListener('abort', cancel);
    if (!done) cancel();
    reader.releaseLock();
  }
}

export function createContextInspectionRoute(operation) {
  if (!["basis", "inspect", "review"].includes(operation)) throw new Error("Unsupported context operation");
  return async (request, env) => {
    const response = (status, body = null) => new Response(body, {status, headers: {
      'content-type': 'application/json', 'cache-control': 'private, no-store',
      'vary': 'Cf-Access-Authenticated-User-Email', 'x-content-type-options': 'nosniff'
    }});
    const url = new URL(request.url), origin = request.headers.get('origin');
    if (request.method !== 'POST') return response(405);
    if (url.search || (origin && origin !== url.origin) ||
        ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site'))) return response(400);
    if (request.headers.get('content-type') !== 'application/json' ||
        ![null, 'identity'].includes(request.headers.get('content-encoding'))) return response(415);
    const email = accessEmail(request);
    if (!email) return response(401);
    const controller = new AbortController();
    let timer;
    try {
      const mapping = JSON.parse(env.BRAIN_CONTEXT_CREDENTIALS);
      const token = Object.hasOwn(mapping, email) ? mapping[email] : null;
      if (typeof token !== 'string' || !/^[A-Za-z0-9._~+/\-]+=*$/.test(token) || token.length > 4096) return response(403);
      if (!env.BRAIN_CONTEXT_SERVICE || typeof env.BRAIN_CONTEXT_SERVICE.fetch !== 'function') return response(503);
      const work = async () => {
        const raw = await bounded(request.body, 65536, controller.signal);
        const reply = await env.BRAIN_CONTEXT_SERVICE.fetch('https://brain-context.internal/' + operation, {
          method: 'POST', headers: {'content-type': 'application/json', 'authorization': 'Bearer ' + token},
          body: raw, signal: controller.signal, redirect: 'error'
        });
        if (reply.status !== 200) {
          if (reply.body) reply.body.cancel().catch(() => {});
          return response([400, 401, 403, 413, 503].includes(reply.status) ? reply.status : 503);
        }
        if (!(reply.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) {
          if (reply.body) reply.body.cancel().catch(() => {});
          return response(503);
        }
        return response(200, await bounded(reply.body, 4194304, controller.signal));
      };
      const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Context inspection deadline')); }, 10000);
      });
      return await Promise.race([work(), deadline]);
    } catch {
      return response(503);
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  };
}
