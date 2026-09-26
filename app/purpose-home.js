/* Purpose-specific home views over the same reader-visible graph and routes.
 * Presentation selects neither authority nor new data sources. A denied graph
 * stays denied; no fallback to another artifact or elevated endpoint is attempted.
 */
(function (global) {
  'use strict';
  var doc = global.document, generation = 0;
  var esc = function (value) { return global.KBNav.esc(value == null ? '' : value); };
  function localRoute(url) { return typeof url === 'string' && /^\/(?!\/)/.test(url) && !/[\\\u0000-\u0020]/.test(url); }
  function array(value) { return Array.isArray(value) ? value : []; }
  function model(home, pages, graph, schema) {
    home = home || {};
    var allowed = new Set((pages || []).filter(function (p) { return p && localRoute(p.url); }).map(function (p) { return p.url; }));
    var nodes = graph && Array.isArray(graph.nodes) ? graph.nodes.filter(function (n) { return n && typeof n === 'object' && typeof n.id === 'string' && typeof n.kind === 'string'; }) : [];
    var nodeKinds = new Map(array(schema && schema.kinds).filter(function (kind) { return kind && typeof kind.id === 'string'; }).map(function (kind) { return [kind.id, kind]; }));
    return {
      primary: array(home.primary).filter(function (task) { return task && allowed.has(task.url); }),
      sections: array(home.sections).filter(function (section) { return section && allowed.has(section.url) && Array.isArray(section.kinds); }).map(function (section) {
        return Object.assign({}, section, {records: nodes.filter(function (n) {
          return section.kinds.some(function (id) {
            if (n.kind === id) return true;
            var kind = nodeKinds.get(id);
            if (!kind) return false;
            var names = typeof kind.node === 'string' ? [kind.node] : array(kind.node);
            var prefixes = array(kind.idPrefixes);
            return names.indexOf(n.kind) >= 0 && (!prefixes.length || prefixes.some(function (prefix) { return typeof prefix === 'string' && n.id.startsWith(prefix); }));
          });
        })});
      }),
      canSearch: allowed.has('/search/'), canInspect: allowed.has('/app/brain.html'),
      canWrite: allowed.has('/knowledge-workbench/') || allowed.has('/authoring/')
    };
  }
  function recordHtml(record, section, canInspect) {
    var title = String(record.title || record.label || record.name || record.text || record.id).slice(0, 180);
    var href = canInspect ? '/app/brain.html?node=' + encodeURIComponent(record.id) : section.url;
    var summary = global.KBEasyView ? global.KBEasyView.summary(record) : ['Source and review status are available in the record.'];
    if (typeof record.source === 'string' && record.source && !(record.evidence && Array.isArray(record.evidence.sources) && record.evidence.sources.length)) summary[0] = 'From: ' + record.source;
    return '<li class="kb-home-record"><a href="' + esc(href) + '">' + esc(title) + '</a>' +
      '<p>' + esc(summary.slice(0, 3).join(' · ')) + '</p></li>';
  }
  function sectionsHtml(view, state) {
    return view.sections.map(function (section) {
      var content;
      if (state === 'loading') content = '<p class="kb-home-empty">Loading visible records…</p>';
      else if (state !== 'ready') content = '<p class="kb-home-empty">' + esc(state) + '</p>';
      else if (!section.records.length) content = '<p class="kb-home-empty">' + esc(section.empty || 'No matching records are visible here yet.') + '</p>';
      else content = '<ul class="kb-home-records">' + section.records.slice(0, 4).map(function (record) { return recordHtml(record, section, view.canInspect); }).join('') + '</ul>';
      return '<article class="kb-home-section" data-section="' + esc(section.id) + '"><header><h2>' + esc(section.title) + '</h2>' +
        '<a href="' + esc(section.url) + '" aria-label="' + esc('Open ' + section.title) + '">Open →</a></header>' +
        '<p class="kb-home-section-desc">' + esc(section.description) + '</p>' + content + '</article>';
    }).join('');
  }
  async function mount(cfg) {
    if (doc.getElementById('kb-purpose-home')) return;
    var request = ++generation;
    var home = await global.KBNav.loadPurposeHome(cfg);
    if (request !== generation || !home || !['company', 'project', 'topic', 'personal'].includes(home.layout)) return;
    // No remount on view changes: a question or chat draft remains in its input.
    if (doc.getElementById('kb-purpose-home')) return;
    var pages = global.KBNav.homePages(cfg.pages || [], cfg.features || {});
    var view = model(home, pages, null);
    var panel = doc.createElement('main'); panel.id = 'kb-purpose-home';
    panel.setAttribute('data-purpose', home.layout); panel.setAttribute('aria-label', home.title);
    panel.innerHTML = '<header class="kb-home-heading"><p class="kb-home-eyebrow">' + esc(home.title) + '</p>' +
      '<h1>' + esc(global.KBNav.brainName(cfg) || home.title) + '</h1>' +
      (global.KBNav.brainPurpose(cfg) ? '<p class="kb-home-purpose">' + esc(global.KBNav.brainPurpose(cfg)) + '</p>' : '') +
      '<p class="kb-home-description">' + esc(home.description) + '</p></header>' +
      '<div class="kb-home-workspace"><div class="kb-home-start">' +
      (view.canSearch ? '<form class="kb-home-search" action="/search/" method="get"><label for="kb-home-question">Find or ask about information</label><div><input id="kb-home-question" name="q" type="search" placeholder="Search this brain…"><button type="submit">Search</button></div></form>' +
        '<div class="kb-home-prompts" aria-label="Suggested questions">' + array(home.prompts).filter(function (p) { return typeof p === 'string'; }).map(function (prompt) { return '<button type="button" data-question="' + esc(prompt) + '">' + esc(prompt) + '</button>'; }).join('') + '</div>' : '<p class="kb-home-empty">Search is not available in this brain’s navigation.</p>') +
      '<nav class="kb-home-tasks" aria-label="' + esc(home.title + ' tasks') + '">' + view.primary.map(function (task) { return '<a href="' + esc(task.url) + '"><strong>' + esc(task.label) + '</strong><span>' + esc(task.description) + '</span></a>'; }).join('') + '</nav>' +
      (!view.canWrite ? '<p class="kb-home-permission">Adding information requires an enabled writing workspace. Ask this brain’s owner for access.</p>' : '<p class="kb-home-permission">Changes require permission in the owning brain.</p>') +
      '<a class="kb-home-recent" href="#recent-list">See recent changes to this brain</a></div>' +
      '<div class="kb-home-sections" aria-live="polite">' + sectionsHtml(view, 'loading') + '</div></div>';
    var hero = doc.querySelector('.hero');
    if (hero) hero.before(panel); else doc.body.appendChild(panel);
    var mark = doc.getElementById('hero-mark-slot');
    if (mark && cfg.branding && cfg.branding.heroMark) {
      mark.className = 'kb-home-brand';
      mark.querySelectorAll('.hero-mark').forEach(function (image) { image.classList.remove('hero-mark'); image.classList.add('kb-home-mark'); });
      panel.querySelector('.kb-home-heading').prepend(mark);
    }
    doc.documentElement.setAttribute('data-kb-purpose-home', home.layout);
    var old = doc.querySelector('.kb-easy-home'); if (old) old.hidden = true;
    panel.querySelectorAll('[data-question]').forEach(function (button) {
      button.addEventListener('click', function () {
        var input = doc.getElementById('kb-home-question');
        // Suggested questions do not replace an unfinished question.
        if (!input.value.trim()) input.value = button.getAttribute('data-question');
        input.focus();
      });
    });
    if (global.KBNav.refresh) global.KBNav.refresh();
    if (!view.sections.length) return;
    var state = 'ready', graph, schema;
    var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 8000);
    try {
      var response = await global.fetch('/app/brain.json', {cache:'no-cache', credentials:'same-origin', signal:controller.signal});
      if (response.status === 401 || response.status === 403) throw new Error('This session cannot read these records. Sign in with an account that has access.');
      if (!response.ok) throw new Error('Records are unavailable right now. Use the available views or try again later.');
      graph = await response.json();
      if (!graph || !Array.isArray(graph.nodes) || graph.nodes.some(function (n) { return !n || typeof n.id !== 'string' || typeof n.kind !== 'string'; })) throw new Error('The brain data could not be read. Try again after it has been refreshed.');
      var schemaResponse = await global.fetch('/brain-schema.json', {cache:'no-cache', credentials:'same-origin', signal:controller.signal});
      if (!schemaResponse.ok) throw new Error('Record types are unavailable in this session. Use the available views or try again later.');
      schema = await schemaResponse.json();
      if (!schema || !Array.isArray(schema.kinds) || schema.kinds.some(function (kind) { return !kind || typeof kind.id !== 'string' || (kind.node != null && typeof kind.node !== 'string' && !(Array.isArray(kind.node) && kind.node.every(function (name) { return typeof name === 'string'; }))); })) throw new Error('The record type definitions could not be read. Try again after they have been refreshed.');
    } catch (error) {
      state = error.name === 'AbortError' ? 'Loading records timed out. Try again later.' : error instanceof SyntaxError ? 'The brain data could not be read. Try again after it has been refreshed.' : error.message;
    } finally { clearTimeout(timeout); }
    if (request !== generation) return;
    view = model(home, pages, graph, schema);
    panel.querySelector('.kb-home-sections').innerHTML = sectionsHtml(view, state);
    panel.setAttribute('data-records-state', state === 'ready' ? 'ready' : 'unavailable');
  }
  global.KBPurposeHome = {mount:mount, model:model, localRoute:localRoute};
})(window);
