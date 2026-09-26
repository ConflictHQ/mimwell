/* Optional, data-only experience renderer. Navigation uses filtered cfg.pages;
 * it never enumerates a federation, reads knowledge or grants access. */
(function (global) {
  'use strict';
  var active = false;
  var CSS_PATH = '/app/experience.css';
  function notice(message) {
    var el = document.getElementById('kb-experience-status');
    if (!el) { el = document.createElement('p'); el.id = 'kb-experience-status'; el.setAttribute('role', 'status'); document.body.prepend(el); }
    el.textContent = message;
  }
  function safeUrl(value) {
    try { var u = new URL(value, global.location.href); return /^https?:$/.test(u.protocol) ? u.href : null; }
    catch (_) { return null; }
  }
  function stylesheet(href) {
    return new Promise(function (resolve, reject) {
      var link = document.createElement('link'); link.rel = 'stylesheet'; link.href = href;
      var timeout = setTimeout(reject, 5000);
      link.onload = function () { clearTimeout(timeout); resolve(); };
      link.onerror = function () { clearTimeout(timeout); reject(); }; document.head.appendChild(link);
    });
  }
  function palette(exp, cfg) {
    var names = { bg: ['--bg', '--kb-bg', '--kb-bg-deep'], surface: ['--surface', '--surface2', '--kb-surface'],
      text: ['--text', '--kb-text'], muted: ['--muted', '--dim', '--kb-text-muted', '--kb-text-faint'],
      border: ['--border', '--border-light', '--kb-border', '--kb-border-light'],
      primary: ['--red', '--kb-primary'], link: ['--blue', '--kb-link'], accent: ['--green', '--kb-accent'] };
    var rules = [];
    ['light', 'dark'].forEach(function (mode) {
      var p = exp.design[mode], css = [];
      Object.keys(names).forEach(function (key) {
        if (!/^#[0-9a-f]{6}$/i.test(p[key])) throw new Error('Invalid palette');
        names[key].forEach(function (name) { css.push(name + ':' + p[key] + '!important'); });
      });
      rules.push('@media screen{:root[data-kb-experience][data-theme="' + mode + '"]{' + css.join(';') + '}}');
    });
    var fonts = (cfg.branding || {}).fonts || {}, declarations = [];
    ['heading', 'body', 'mono'].forEach(function (role) {
      if (fonts[role] && /^[a-zA-Z0-9 ,'-]+$/.test(fonts[role])) declarations.push('--kb-font-' + role + ':' + fonts[role] + '!important');
    });
    declarations.push('--kb-experience-radius:' + Math.max(0, Math.min(20, exp.design.radius)) + 'px');
    rules.push(':root[data-kb-experience]{' + declarations.join(';') + '}');
    var style = document.createElement('style'); style.id = 'kb-experience-palette'; style.textContent = rules.join('\n'); document.head.appendChild(style);
  }
  function localFonts(exp) {
    if (exp.fontMode !== 'local') return;
    if (!global.FontFace || !global.crypto || !global.crypto.subtle) { notice('Local fonts unavailable; using system fallbacks.'); return; }
    (exp.localFonts || []).forEach(function (font) {
      if (!/^assets\/fonts\/[a-zA-Z0-9_-]+\.woff2?$/.test(font.path)) return;
      var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 10000);
      fetch('/' + font.path, { cache: 'no-cache', redirect: 'error', signal: controller.signal }).then(async function (r) {
        if (!r.ok) throw new Error('Font unavailable');
        if (Number(r.headers.get('content-length')) > 2097152 || !r.body) throw new Error('Font too large or unavailable');
        var reader = r.body.getReader(), chunks = [], count = 0;
        while (true) {
          var item = await reader.read(); if (item.done) break;
          count += item.value.byteLength;
          if (count > 2097152) { await reader.cancel(); throw new Error('Font too large'); }
          chunks.push(item.value);
        }
        var data = new Uint8Array(count), position = 0;
        chunks.forEach(function (chunk) { data.set(chunk, position); position += chunk.length; });
        return data.buffer;
      }).then(function (bytes) {
        if (bytes.byteLength > 2097152) throw new Error('Font too large');
        return global.crypto.subtle.digest('SHA-256', bytes).then(function (hash) {
          var actual = Array.from(new Uint8Array(hash)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join('');
          if (actual !== font.sha256) throw new Error('Font changed');
          return new FontFace(font.family, bytes, { weight: font.weight }).load();
        });
      }).then(function (face) { document.fonts.add(face); }).catch(function () { notice('Local fonts unavailable; using system fallbacks.'); }).finally(function () { clearTimeout(timeout); });
    });
  }
  function navigation(exp, cfg) {
    var pages = global.KBNav.visiblePages(cfg.pages || [], cfg.features).filter(function (p) { return p && safeUrl(p.url); });
    var nav = document.createElement('nav'); nav.id = 'kb-experience-nav'; nav.setAttribute('aria-label', 'Brain views');
    var button = document.createElement('button'); button.type = 'button'; button.id = 'kb-experience-toggle';
    button.textContent = 'Views'; button.setAttribute('aria-controls', nav.id); button.setAttribute('aria-expanded', 'false');
    var host = document.querySelector('.topbar') || document.body;
    host.appendChild(button);
    function close() { nav.classList.remove('is-open'); button.setAttribute('aria-expanded', 'false'); }
    button.addEventListener('click', function () { var open = nav.classList.toggle('is-open'); button.setAttribute('aria-expanded', String(open)); });
    nav.addEventListener('keydown', function (event) { if (event.key === 'Escape') { close(); button.focus(); } });
    var search;
    if (exp.navigation.search) {
      search = document.createElement('input'); search.type = 'search'; search.placeholder = 'Find a view'; search.setAttribute('aria-label', 'Find a view'); nav.appendChild(search);
    }
    var contents = document.createElement('div'); nav.appendChild(contents);
    function render() {
      var query = search ? search.value.toLocaleLowerCase() : '';
      var visible = pages.filter(function (p) { return [p.label, p.description, p.group].join(' ').toLocaleLowerCase().includes(query); });
      contents.replaceChildren();
      global.KBNav.groupPages(visible).forEach(function (group) {
        var section = document.createElement('section'), heading = document.createElement('h2'); heading.textContent = group.group; section.appendChild(heading);
        group.pages.forEach(function (p) {
          var link = document.createElement('a'); link.href = safeUrl(p.url); link.textContent = p.label || p.url;
          if (new URL(link.href).origin !== global.location.origin) { link.target = '_blank'; link.rel = 'noopener'; link.setAttribute('aria-label', (p.label || p.url) + ' (external)'); }
          if (new URL(link.href).origin === global.location.origin && new URL(link.href).pathname === global.location.pathname) link.setAttribute('aria-current', 'page');
          section.appendChild(link);
        });
        contents.appendChild(section);
      });
      if (!visible.length) { var empty = document.createElement('p'); empty.setAttribute('role', 'status'); empty.textContent = 'No matching views'; contents.appendChild(empty); }
    }
    if (search) search.addEventListener('input', render);
    global.addEventListener('kb-view-change', render);
    render(); host.insertAdjacentElement('afterend', nav);
    if (exp.entryFromVisiblePages && global.location.pathname === '/' && !global.location.search && !global.location.hash) {
      var first = pages.map(function (p) { return new URL(safeUrl(p.url)); }).find(function (u) {
        return u.origin === global.location.origin && u.pathname !== '/';
      });
      if (first) global.location.replace(first.href);
    }
  }
  function valid(exp) {
    return exp && ['1.0','1.1'].includes(exp.protocolVersion) && exp.selection && typeof exp.selection.id === 'string' &&
      exp.design && exp.design.light && exp.design.dark && Number.isInteger(exp.design.radius) &&
      exp.layout && ['reading', 'workbench'].includes(exp.layout.mode) &&
      ['comfortable', 'compact'].includes(exp.layout.density) && ['standard', 'wide'].includes(exp.layout.width) &&
      ['auto', 'stacked'].includes(exp.layout.responsive) && exp.navigation &&
      ['top', 'rail'].includes(exp.navigation.mode) && typeof exp.navigation.search === 'boolean' &&
      typeof exp.navigation.breadcrumbs === 'boolean' && ['system', 'local'].includes(exp.fontMode) &&
      Array.isArray(exp.localFonts) && exp.localFonts.length <= 6 && exp.localFonts.every(function (f) {
        return f && typeof f.path === 'string' && typeof f.family === 'string' && /^[0-9a-f]{64}$/.test(f.sha256);
      });
  }
  function cleanup() {
    Array.from(document.documentElement.attributes).forEach(function (a) {
      if (/^data-kb-(experience|layout-|navigation|breadcrumbs|owner-empty)/.test(a.name)) document.documentElement.removeAttribute(a.name);
    });
    ['kb-experience-nav', 'kb-experience-toggle', 'kb-experience-palette'].forEach(function (id) {
      var el = document.getElementById(id); if (el) el.remove();
    });
  }
  function mount(cfg) {
    var exp = cfg && cfg.portal && cfg.portal.experience;
    if (active || !exp || !['1.0','1.1'].includes(exp.protocolVersion)) return Promise.resolve(false);
    if (!valid(exp)) { notice('Presentation unavailable; standard navigation remains available.'); return Promise.resolve(false); }
    active = true;
    return Promise.all([stylesheet(CSS_PATH), document.querySelector('link[href^="/app/theme.css"]') ? Promise.resolve() : stylesheet('/app/theme.css')]).then(function () {
      palette(exp, cfg);
      navigation(exp, cfg);
      var root = document.documentElement;
      root.setAttribute('data-kb-experience', exp.selection.id);
      root.setAttribute('data-kb-owner-empty', String(!global.KBNav.ownerName(cfg.branding)));
      ['mode', 'density', 'width', 'responsive'].forEach(function (key) { root.setAttribute('data-kb-layout-' + key, exp.layout[key]); });
      root.setAttribute('data-kb-navigation', exp.navigation.mode);
      root.setAttribute('data-kb-breadcrumbs', String(exp.navigation.breadcrumbs));
      localFonts(exp);
      return true;
    }).catch(function () { active = false; cleanup(); notice('Presentation unavailable; standard navigation remains available.'); return false; });
  }
  global.KBExperience = { mount: mount };
})(window);
