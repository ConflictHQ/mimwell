/* ── Page shell (frontend pass 2, W1.6) ───────────────────────────────────────
 * The chrome every page needs, mounted once from config: brand variables,
 * brand name, top-nav (through KBNav), owner mark, footer, document title.
 * kind-page.js and every bespoke surface call KBShell.mount() instead of
 * carrying the block themselves. Resolves with the loaded config so the caller
 * can read features/pages/portal without a second fetch. Null-safe: a page
 * missing any chrome element simply skips it.
 */
(function (global) {
  'use strict';

  var VAR_MAP = {
    primary: '--kb-primary', link: '--kb-link', accent: '--kb-accent', bg: '--kb-bg',
    bgDeep: '--kb-bg-deep', surface: '--kb-surface', border: '--kb-border',
    borderLight: '--kb-border-light', text: '--kb-text', textMuted: '--kb-text-muted',
    textFaint: '--kb-text-faint'
  };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fetchJson(url, fallback) {
    if (url !== '/client.config.json') return fetch(url, {cache:'no-cache'}).then(function (r) { return r.ok ? r.json() : fallback; }).catch(function () { return fallback; });
    var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); },15000);
    return fetch(url, { cache: 'no-cache', signal:controller.signal })
      .then(async function (r) {
        if (!r.ok || !r.body || Number(r.headers.get('content-length')) > 4194304) return fallback;
        var reader = r.body.getReader(), parts = [], size = 0;
        while (true) {
          var item = await reader.read(); if (item.done) break;
          size += item.value.byteLength;
          if (size > 4194304) { await reader.cancel(); return fallback; }
          parts.push(item.value);
        }
        var bytes = new Uint8Array(size), offset = 0;
        parts.forEach(function (part) { bytes.set(part,offset); offset += part.length; });
        return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      })
      .catch(function () { return fallback; })
      .finally(function () { clearTimeout(timeout); });
  }


  function applyBranding(cfg) {
    var b = cfg.branding || {}, colors = b.colors || {}, fonts = b.fonts || {};
    var root = document.documentElement.style;
    Object.keys(VAR_MAP).forEach(function (k) { if (colors[k]) root.setProperty(VAR_MAP[k], colors[k]); });
    if (fonts.heading) root.setProperty('--kb-font-heading', fonts.heading);
    if (fonts.body) root.setProperty('--kb-font-body', fonts.body);
    if (fonts.mono) root.setProperty('--kb-font-mono', fonts.mono);
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el && val != null) el.textContent = val;
  }

  // mount({ title }) -> Promise<cfg>. `title` (optional) is the page's own
  // title; the document title becomes "<brand> — <title>".
  function mount(opts) {
    opts = opts || {};
    return fetchJson('/client.config.json', {}).then(function (cfg) {
      applyBranding(cfg);
      var client = cfg.client || {};
      var brainName = global.KBNav ? global.KBNav.brainName(cfg) : (client.name || client.shortName || '');
      var brand = brainName || client.shortName || '';
      setText('brand-name', client.shortName || brainName || '');
      if (global.KBNav) {
        global.KBNav.config(cfg);
        setText('footer-text', [client.shortName || brainName, global.KBNav.ownerName(cfg.branding)].filter(Boolean).join(' · '));
        var nav = document.getElementById('topnav');
        if (nav) global.KBNav.topnav(nav, cfg.pages || [], { features: cfg.features });
      }
      var title = opts.title || (document.querySelector('.page-title') || {}).textContent || '';
      if (title) document.title = (brand ? brand + ' — ' : '') + String(title).trim();
      return global.KBNav && global.KBNav.easyReady ? global.KBNav.easyReady().then(function () { return cfg; }) : cfg;
    });
  }

  global.KBShell = { mount: mount, esc: esc, fetchJson: fetchJson, applyBranding: applyBranding };
})(window);
