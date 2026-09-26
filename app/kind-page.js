/* ── Schema-rendered kind page ────────────────────────────────────────────────
 * One renderer for every flat-record page (frontend pass 1, buildout W1.5;
 * #54 slice 2 scoped up from decisions-only). A page shell declares WHICH kinds
 * it shows and nothing else:
 *
 *     <main class="kind-page" data-kb-kinds="decision,open-question"></main>
 *     <script src="/app/kind-page.js" defer></script>
 *
 * Everything the shells used to duplicate — config fetch, brand variables,
 * top-nav, owner mark, footer, document title, the view toggle, label tabs,
 * list, pager and empty states — lives here once. WHAT a record looks like comes
 * from app/kinds.json (scripts/gen-kinds.py): the records key, the declared
 * fields, and the display roles derived from the artifact schema. Delete a
 * field from the schema and it disappears from the page with no edit here.
 *
 * Shared seams reused, never re-implemented: KBShell.mount (chrome: brand,
 * nav, owner mark, footer, title — W1.6), KBNav (grouping, co-brand), theme.js
 * (theme toggle attaches itself to .topbar), the --kb-* contract (theming.md).
 *
 * Exposes a global `KBKindPage` so plain <script src> pages can use it; the
 * module mounts itself on DOMContentLoaded when a .kind-page host exists.
 * Every method is null-safe and renders clean empty states.
 */
(function (global) {
  'use strict';

  var PER_PAGE = 25;
  var ALL_TAB = '__all__';

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fetchJson(url, fallback) {
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

  // ── Branding (the block every shell used to carry) ────────────────────────
  var VAR_MAP = {
    primary: '--kb-primary', link: '--kb-link', accent: '--kb-accent', bg: '--kb-bg',
    bgDeep: '--kb-bg-deep', surface: '--kb-surface', border: '--kb-border',
    borderLight: '--kb-border-light', text: '--kb-text', textMuted: '--kb-text-muted',
    textFaint: '--kb-text-faint'
  };
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

  // ── Record rendering, driven by display roles ─────────────────────────────
  function statusClass(v) {
    var s = String(v == null ? '' : v).trim().toLowerCase();
    if (!s) return '';
    if (/^(open|active|in[- ]progress|doing)$/.test(s)) return 'kp-status-open';
    if (/^(closed|resolved|answered|done|complete|completed|shipped)$/.test(s)) return 'kp-status-closed';
    if (/^(deferred|blocked|on[- ]hold|parked)$/.test(s)) return 'kp-status-deferred';
    if (/^(high|critical|severe)$/.test(s)) return 'kp-status-high';
    return 'kp-status-other';
  }

  function sessionLink(id) {
    id = id && String(id).trim();
    return id ? '<a class="kp-session" href="/app/session.html?id=' + esc(encodeURIComponent(id)) + '">View session →</a>' : '';
  }

  function linkHtml(v, label) {
    v = v && String(v).trim();
    if (!v) return '';
    var href = /^mailto:|^https?:\/\/|^\//.test(v) ? v : (/@/.test(v) ? 'mailto:' + v : v);
    // Schema roles choose fields, not executable URL schemes. A generic record
    // may come from an untrusted source; rejected links remain readable text.
    try {
      if (/[\u0000-\u001f\u007f]/.test(href) ||
          !/^(https?:|mailto:)$/.test(new URL(href, global.location.href).protocol)) return esc(label || v);
    } catch (_) { return esc(label || v); }
    return '<a class="kp-link" href="' + esc(href) + '" target="_blank" rel="noopener">' + esc(label || v) + '</a>';
  }

  function chips(values, cls) {
    return (values || []).filter(Boolean).map(function (v) {
      return '<span class="' + cls + '">' + esc(v) + '</span>';
    }).join('');
  }

  function recordHtml(kind, r) {
    var d = kind.display;
    var title = d.title ? r[d.title] : null;
    var body = d.body ? r[d.body] : null;
    var statuses = (d.status || []).map(function (f) { return r[f]; }).filter(Boolean);
    var labels = [];
    (d.labels || []).forEach(function (f) { if (Array.isArray(r[f])) labels = labels.concat(r[f]); });
    var meta = (d.meta || []).map(function (f) {
      var v = r[f];
      if (v == null || v === '' || typeof v === 'object') return '';
      return '<span class="kp-meta-item"><span class="kp-meta-key">' + esc(f) + '</span> ' + esc(v) + '</span>';
    }).join('');
    var owner = (d.owner || []).map(function (f) { return r[f]; }).filter(Boolean).join(', ');
    var subs = kind.fields.filter(function (f) {
      return f.type === 'array' && f.items === 'string' && (d.labels || []).indexOf(f.name) === -1 && Array.isArray(r[f.name]) && r[f.name].length;
    }).map(function (f) {
      return '<div class="kp-sub"><div class="kp-sub-key">' + esc(f.name) + '</div><ul class="kp-sub-list">' +
        r[f.name].map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></div>';
    }).join('');

    return '<li class="kp-entry" data-kind="' + esc(kind.id) + '">' +
      '<div class="kp-entry-head">' +
        (d.date && r[d.date] ? '<span class="kp-date">' + esc(r[d.date]) + '</span>' : '') +
        statuses.map(function (s) { return '<span class="kp-status ' + statusClass(s) + '">' + esc(s) + '</span>'; }).join('') +
      '</div>' +
      '<h3 class="kp-title">' + esc(title || '(untitled)') + '</h3>' +
      (body ? '<p class="kp-body">' + esc(body) + '</p>' : '') +
      (global.KBEasyView ? global.KBEasyView.summaryHtml(r) : '') +
      subs +
      (labels.length ? '<div class="kp-labels">' + chips(labels, 'kp-label') + '</div>' : '') +
      '<div class="kp-entry-foot">' +
        (owner ? '<span class="kp-owner">' + esc(owner) + '</span>' : '') +
        meta +
        (d.link && r[d.link] ? linkHtml(r[d.link], r.linkLabel) : '') +
        (d.session && r[d.session] ? sessionLink(r[d.session]) : '') +
      '</div>' +
    '</li>';
  }

  // ── Nested lists (#76) ──────────────────────────────────────────────────
  // A tree kind (kinds.json: renderable=false, a `nested` array) stays a
  // bespoke page — a flat list would flatten the tree into nonsense — but its
  // nested lists are still declared, not hand-described. `nestedDescriptor`
  // looks one up by name (e.g. a roadmap track's "phases"); `nestedRecordHtml`
  // renders its records with the exact same role-driven markup and CSS
  // classes as a top-level kind, so a custom page can opt into it explicitly
  // for the parts of its tree that are themselves flat lists, without the
  // generic renderer ever mounting itself over a tree kind automatically.
  function nestedDescriptor(kind, name) {
    var list = (kind && kind.nested) || [];
    for (var i = 0; i < list.length; i++) { if (list[i].name === name) return list[i]; }
    return null;
  }

  function nestedRecordHtml(descriptor, records) {
    if (!descriptor) return '';
    if (!records || !records.length) {
      return '<div class="kp-state"><div class="kp-state-title">Nothing here</div><div>No ' +
        esc(descriptor.name) + ' recorded yet.</div></div>';
    }
    var pseudoKind = { id: descriptor.name, fields: descriptor.fields, display: descriptor.display };
    return '<ul class="kp-list">' + records.map(function (r) { return recordHtml(pseudoKind, r); }).join('') + '</ul>';
  }

  // ── Page state: one slice per kind so toggling preserves each view ─────────
  function makeView(kind) {
    return { kind: kind, rows: [], tab: ALL_TAB, page: 1, tabs: [], count: 0 };
  }

  function labelsOf(kind, r) {
    var out = [];
    (kind.display.labels || []).forEach(function (f) { if (Array.isArray(r[f])) out = out.concat(r[f]); });
    return out;
  }

  function buildTabs(view) {
    var seen = {};
    view.rows.forEach(function (r) { labelsOf(view.kind, r).forEach(function (l) { seen[l] = true; }); });
    var ordered = Object.keys(seen).sort(function (a, b) { return a.localeCompare(b); });
    return [{ id: ALL_TAB, label: 'All' }].concat(ordered.map(function (l) { return { id: l, label: l }; }));
  }

  function rowsForTab(view, tab) {
    if (tab === ALL_TAB) return view.rows;
    return view.rows.filter(function (r) { return labelsOf(view.kind, r).indexOf(tab) !== -1; });
  }

  function byDateDesc(kind) {
    var f = kind.display.date;
    if (!f) return null;
    return function (a, b) { return String(b[f] || '').localeCompare(String(a[f] || '')); };
  }

  // ── Mount ─────────────────────────────────────────────────────────────────
  function mount(host) {
    var ids = (host.getAttribute('data-kb-kinds') || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    if (!ids.length) { host.innerHTML = '<div class="kp-state"><div class="kp-state-title">No kinds declared</div><div>Add data-kb-kinds="…" to the page host.</div></div>'; return; }

    host.innerHTML =
      '<div class="kp-toggle" role="group" aria-label="Switch view" hidden></div>' +
      '<nav class="kp-tabs" role="tablist" aria-label="Filter by label"></nav>' +
      '<div class="kp-wrap"><div class="kp-results"><div class="kp-state"><div class="kp-spinner"></div><div class="kp-state-title">Loading</div></div></div>' +
      '<nav class="kp-pager" aria-label="Pagination" hidden></nav></div>';

    var toggleEl = host.querySelector('.kp-toggle');
    var tabsEl = host.querySelector('.kp-tabs');
    var resultsEl = host.querySelector('.kp-results');
    var pagerEl = host.querySelector('.kp-pager');
    var state = { views: [], active: 0, brand: '' };
    var cur = function () { return state.views[state.active]; };

    function syncHeader() {
      var v = cur(); if (!v) return;
      var h1 = document.querySelector('.page-title');
      if (h1 && h1.getAttribute('data-kb-auto') !== 'false') h1.textContent = v.kind.title + (v.kind.title.slice(-1) === 's' ? '' : 's');
      var sub = document.querySelector('.page-subtitle');
      if (sub && !sub.textContent.trim()) sub.textContent = v.kind.description || '';
      document.title = (state.brand ? state.brand + ' — ' : '') + (h1 ? h1.textContent : v.kind.title);
    }

    function renderToggle() {
      if (state.views.length < 2) { toggleEl.hidden = true; return; }
      toggleEl.hidden = false;
      toggleEl.innerHTML = state.views.map(function (v, i) {
        return '<button class="kp-view-btn' + (i === state.active ? ' active' : '') + '" type="button" data-view="' + i + '">' +
          esc(v.kind.title) + 's <span class="kp-count">(' + v.count + ')</span></button>';
      }).join('');
    }

    function renderTabs() {
      var v = cur();
      if (v.tabs.length <= 1) { tabsEl.innerHTML = ''; return; }
      tabsEl.innerHTML = v.tabs.map(function (t) {
        var active = t.id === v.tab;
        return '<button class="kp-tab' + (active ? ' active' : '') + '" type="button" role="tab" aria-selected="' + active + '" data-tab="' + esc(t.id) + '">' +
          esc(t.label) + ' <span class="kp-tab-count">(' + rowsForTab(v, t.id).length + ')</span></button>';
      }).join('');
    }

    function renderPager(total) {
      var v = cur();
      if (total <= 1) { pagerEl.hidden = true; pagerEl.innerHTML = ''; return; }
      pagerEl.hidden = false;
      pagerEl.innerHTML =
        '<button class="kp-pager-btn" type="button" data-nav="prev"' + (v.page <= 1 ? ' disabled' : '') + '>← Prev</button>' +
        '<span class="kp-pager-info">Page ' + v.page + ' of ' + total + '</span>' +
        '<button class="kp-pager-btn" type="button" data-nav="next"' + (v.page >= total ? ' disabled' : '') + '>Next →</button>';
    }

    function render() {
      var v = cur();
      var filtered = rowsForTab(v, v.tab);
      if (!filtered.length) {
        var noun = v.kind.title.toLowerCase() + 's';
        resultsEl.innerHTML = '<div class="kp-state"><div class="kp-state-title">Nothing here</div><div>' +
          (v.rows.length ? 'No ' + esc(noun) + ' match the current filter.' : 'No ' + esc(noun) + ' have been recorded yet.') + '</div></div>';
        renderPager(1); renderTabs(); return;
      }
      var total = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
      if (v.page > total) v.page = total;
      var start = (v.page - 1) * PER_PAGE;
      resultsEl.innerHTML = '<ul class="kp-list">' + filtered.slice(start, start + PER_PAGE).map(function (r) { return recordHtml(v.kind, r); }).join('') + '</ul>';
      renderPager(total); renderTabs();
    }

    toggleEl.addEventListener('click', function (e) {
      var btn = e.target.closest('.kp-view-btn'); if (!btn) return;
      var i = Number(btn.getAttribute('data-view'));
      if (i === state.active) return;
      state.active = i; renderToggle(); syncHeader(); render();
    });
    tabsEl.addEventListener('click', function (e) {
      var btn = e.target.closest('.kp-tab'); if (!btn) return;
      var v = cur(), tab = btn.getAttribute('data-tab');
      if (tab === v.tab) return;
      v.tab = tab; v.page = 1; render();
    });
    pagerEl.addEventListener('click', function (e) {
      var btn = e.target.closest('.kp-pager-btn'); if (!btn || btn.disabled) return;
      var v = cur();
      v.page += btn.getAttribute('data-nav') === 'prev' ? -1 : 1;
      render(); window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // Chrome through the shared shell (W1.6) + kinds, in parallel; each degrades
    // to empty, never errors. Without shell.js on the page the chrome block runs
    // inline so an older shell still renders.
    var chrome = global.KBShell ? global.KBShell.mount() : fetchJson('/client.config.json', {}).then(function (cfg) {
      applyBranding(cfg);
      var client = cfg.client || {};
      var brainName = global.KBNav ? global.KBNav.brainName(cfg) : (client.name || client.shortName || '');
      setText('brand-name', client.shortName || brainName || '');
      if (global.KBNav) {
        setText('footer-text', [client.shortName || brainName, global.KBNav.ownerName(cfg.branding)].filter(Boolean).join(' · '));
        var nav = document.getElementById('topnav');
        if (nav) global.KBNav.topnav(nav, cfg.pages || [], { features: cfg.features });
        if (global.KBNav.applyOwnerBrand) global.KBNav.applyOwnerBrand(cfg.branding);
      }
      return cfg;
    });
    Promise.all([chrome, fetchJson('/app/kinds.json', { kinds: [] })]).then(function (res) {
      var cfg = res[0], kinds = res[1].kinds || [];
      function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
      // Purpose-neutral owner seam (#206, Phase 1: alias): the record page needs
      // SOME resolvable name, from brain.name or the client.* alias — not
      // specifically cfg.client.name, so a brain with no `client` block at all
      // still renders. cfg.client, when present at all, must still be an object.
      var recordName = global.KBNav ? global.KBNav.brainName(cfg) : (object(cfg) && object(cfg.client) ? (cfg.client.name || cfg.client.shortName || '') : '');
      if (!object(cfg) || (cfg.client !== undefined && !object(cfg.client)) || typeof recordName !== 'string' || !recordName ||
          !object(cfg.branding) || !object(cfg.assistant) || !Array.isArray(cfg.pages) ||
          cfg.pages.some(function (page) { return !object(page) || typeof page.url !== 'string' || typeof page.label !== 'string'; })) {
        throw new Error('Record configuration unavailable');
      }
      if (Object.prototype.hasOwnProperty.call(cfg, 'portal') && !object(cfg.portal)) throw new Error('Invalid portal');
      if (cfg.portal && Object.prototype.hasOwnProperty.call(cfg.portal, 'experience')) {
        var exp = cfg.portal.experience;
        if (!object(exp) || !['1.0','1.1'].includes(exp.protocolVersion) || !object(exp.selection) ||
            typeof exp.selection.id !== 'string' || !object(exp.design) || !object(exp.design.light) ||
            !object(exp.design.dark) || !Number.isInteger(exp.design.radius) || !object(exp.layout) ||
            !['reading','workbench'].includes(exp.layout.mode) || !['comfortable','compact'].includes(exp.layout.density) ||
            !['standard','wide'].includes(exp.layout.width) || !['auto','stacked'].includes(exp.layout.responsive) ||
            !object(exp.navigation) || !['top','rail'].includes(exp.navigation.mode) ||
            typeof exp.navigation.search !== 'boolean' || typeof exp.navigation.breadcrumbs !== 'boolean' ||
            !['system','local'].includes(exp.fontMode) || !Array.isArray(exp.localFonts) ||
            Object.prototype.hasOwnProperty.call(exp,'recordViewDescriptors') && !Object.prototype.hasOwnProperty.call(exp,'recordViews')) {
          throw new Error('Invalid selected experience');
        }
      }
      var client = cfg.client || {};
      state.brand = recordName || client.shortName || '';

      // Explicitly selected record IA owns this page, including failure states.
      // Missing/invalid configuration must not widen into the legacy full list.
      var experience = cfg.portal && cfg.portal.experience;
      if (experience && Object.prototype.hasOwnProperty.call(experience, 'recordViews')) {
        function unavailable() {
          host.innerHTML = '<p role="status">Selected record view unavailable.</p>';
        }
        if (experience.protocolVersion !== '1.1') { unavailable(); return; }
        return new Promise(function (resolve, reject) {
          if (global.KBRecordViews) { resolve(); return; }
          var script = document.createElement('script'); script.src = '/app/record-views.js';
          script.onload = resolve; script.onerror = reject; document.head.appendChild(script);
        }).then(function () {
          var selected = global.KBRecordViews.pageConfig(experience.recordViews, kinds, global.location.pathname, ids);
          if (!selected) {
            // A page absent from the selected record IA retains its legacy view.
            // Mount with the already-read config stripped only for this invocation.
            return legacy();
          }
          return global.KBRecordViews.verifyDescriptors(selected, kinds, experience.recordViewDescriptors).then(function () {
            global.KBRecordViews.mount(host, selected, kinds, recordHtml);
          });
        }).catch(unavailable);
      }
      return legacy();

      function legacy() {
      var byId = {}; kinds.forEach(function (k) { byId[k.id] = k; });
      var missing = ids.filter(function (id) { return !byId[id] || !byId[id].renderable; });
      state.views = ids.filter(function (id) { return byId[id] && byId[id].renderable; }).map(function (id) { return makeView(byId[id]); });
      if (!state.views.length) {
        resultsEl.innerHTML = '<div class="kp-state"><div class="kp-state-title">Not renderable</div><div>' +
          esc(missing.join(', ')) + ': ' + esc(missing.map(function (id) { return byId[id] ? byId[id].reason : 'unknown kind'; }).join('; ')) + '</div></div>';
        return;
      }
      return Promise.all(state.views.map(function (v) {
        return fetch('/' + v.kind.artifact.replace(/^\//, ''), { cache: 'no-cache' }).then(function (response) {
          if (!response.ok) throw new Error('Record source unavailable');
          return response.json();
        }).then(function (data) {
          if (!data || !Array.isArray(data[v.kind.records])) throw new Error('Invalid record collection');
          var rows = data[v.kind.records].slice();
          var sort = byDateDesc(v.kind); if (sort) rows.sort(sort);
          v.rows = rows; v.tabs = buildTabs(v);
          v.count = typeof data.count === 'number' ? data.count : rows.length;
        });
      })).then(function () { renderToggle(); syncHeader(); render(); }).catch(function () {
        resultsEl.innerHTML = '<div class="kp-state" role="status"><div class="kp-state-title">Records unavailable</div>' +
          '<div>The selected records could not be loaded. Retry when the source is available.</div></div>';
      });
      }
    }).catch(function () {
      host.innerHTML = '<p role="status">Record configuration unavailable.</p>';
    });
  }

  function mountAll() {
    Array.prototype.forEach.call(document.querySelectorAll('.kind-page[data-kb-kinds]'), mount);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAll);
  else mountAll();

  global.KBKindPage = { mount: mount, recordHtml: recordHtml, nestedDescriptor: nestedDescriptor, nestedRecordHtml: nestedRecordHtml, esc: esc };
})(window);
