import {parse} from './app-vendor/es-module-lexer.js';
async function startBundle() {
const assets = JSON.parse(document.getElementById('brain-app-assets').textContent);
const base = 'https://brain-app.invalid/';
const sources = new Map(Object.entries(assets).map(([path, asset]) => [new URL(path, base).href, asset]));
const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const text = value => new TextDecoder().decode(bytes(value));
const urls = new Map();
const resolve = (name, parent = base) => {
  const url = new URL(name, parent).href;
  if (!url.startsWith(base) || !sources.has(url))
    throw new Error('App asset is not packaged: ' + name);
  return url;
};
const rewrite = (source, parent) => {
  const [imports] = parse(source);
  for (const entry of [...imports].reverse()) {
    let replacement;
    if (entry.d === -2) replacement = '({url:' + JSON.stringify(parent) + '})';
    else {
      if (entry.n === undefined && entry.d >= 0) {
        replacement = 'globalThis.__brainImport(' + source.slice(entry.s, entry.e) + ',' + JSON.stringify(parent) + ')';
        source = source.slice(0, entry.ss) + replacement + source.slice(entry.se);
        continue;
      }
      if (entry.n === undefined) throw new Error('Unsupported module import');
      const target = resolve(entry.n, parent);
      replacement = entry.d >= 0 ? JSON.stringify(target) : target;
    }
    source = source.slice(0, entry.s) + replacement + source.slice(entry.e);
  }
  return source;
};
for (const [path, asset] of Object.entries(assets)) {
  const url = new URL(path, base).href;
  const code = /\.(m?js)$/.test(path);
  const content = code ? rewrite(text(asset.data), url) : bytes(asset.data);
  urls.set(url, URL.createObjectURL(new Blob([content], {type: asset.type})));
}
for (const [path, asset] of Object.entries(assets)) {
  if (!path.endsWith('.css')) continue;
  const parent = new URL(path, base).href;
  const css = text(asset.data).replace(/url\(\s*(['"]?)([^)'"\s]+)\1\s*\)/g, (match, quote, name) =>
    name.startsWith('data:') || name.startsWith('#') ? match : 'url("' + urls.get(resolve(name, parent)) + '")');
  URL.revokeObjectURL(urls.get(parent));
  urls.set(parent, URL.createObjectURL(new Blob([css], {type: 'text/css'})));
}
window.brain = Object.freeze({...window.brain, asset: name => urls.get(resolve(name))});
globalThis.__brainImport = (name, parent) => import(resolve(name, parent));
const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input, options) => {
  const name = input instanceof Request ? input.url : String(input);
  if (name.startsWith('blob:') || name.startsWith('data:')) return originalFetch(input, options);
  const url = resolve(name);
  return originalFetch(urls.get(url), options);
};
const map = document.createElement('script');
map.type = 'importmap';
map.textContent = JSON.stringify({imports: Object.fromEntries(urls)});
document.head.append(map);
for (const element of document.querySelectorAll('img[src],source[src],video[src],audio[src],link[rel="stylesheet"]')) {
  const attr = element.tagName === 'LINK' ? 'href' : 'src';
  const name = element.getAttribute(attr);
  if (!name || name.startsWith('data:')) continue;
  element.setAttribute(attr, urls.get(resolve(name)));
}
for (const placeholder of document.querySelectorAll('script[data-brain-script]')) {
  const script = document.createElement('script');
  const module = placeholder.dataset.brainScript === 'module';
  if (module) script.type = 'module';
  const src = placeholder.dataset.brainSrc;
  if (module) {
    script.src = src ? urls.get(resolve(src)) : URL.createObjectURL(new Blob([rewrite(placeholder.textContent, base + 'index.html')], {type: 'text/javascript'}));
    const loaded = new Promise((resolve, reject) => {script.onload = resolve; script.onerror = reject;});
    placeholder.replaceWith(script);
    await loaded;
  } else {
    script.textContent = src ? text(sources.get(resolve(src)).data) : placeholder.textContent;
    placeholder.replaceWith(script);
  }
}

}
startBundle().catch(error => {
  console.error(error);
  const message = document.createElement('pre');
  message.setAttribute('role', 'alert');
  message.textContent = 'App could not start: ' + error.message;
  document.body.append(message);
});
