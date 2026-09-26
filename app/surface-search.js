/* ── Resolution-aware search (W1.7) ──────────────────────────────────────────
 * One box, several resolutions, and every hit says WHICH resolution answered:
 *   exact       — a brain node whose id or title matches (app/brain.json)
 *   lexical     — a knowledge-pack entry whose title/summary carries the terms
 *   relational  — nodes one hop from an exact hit (edges in app/brain.json)
 * Semantic is listed but answered only when the vector index is present
 * (features.semantic_search + app/brain.vec.json); otherwise the page says so
 * rather than pretending. Client-side over the served projections — no worker
 * change, no bespoke data path.
 */
(function (global) {
  'use strict';
  var esc = function (s) { return global.KBShell.esc(s); };
  var fetchJson = function (u, f) { return global.KBShell.fetchJson(u, f); };
  var MAX = 12;

  function terms(q) { return String(q || '').toLowerCase().split(/[^a-z0-9]+/).filter(function (t) { return t.length > 1; }); }
  function score(text, ts) {
    var t = String(text || '').toLowerCase(); var n = 0;
    ts.forEach(function (x) { if (t.indexOf(x) !== -1) n++; });
    return n;
  }
  function hit(res, title, body, href, extra) {
    return '<li class="ks-entry"><div class="ks-entry-head"><span class="ks-res">' + esc(res) + '</span>' + (extra || '') + '</div>' +
      '<h3 class="ks-entry-title">' + (href ? '<a class="ks-link" href="' + esc(href) + '">' + esc(title) + '</a>' : esc(title)) + '</h3>' +
      (body ? '<p class="ks-entry-body">' + esc(String(body).slice(0, 240)) + '</p>' : '') + '</li>';
  }
  function nodeHref(n) { return '/app/brain.html?id=' + encodeURIComponent(n.id); }

  function run(q, data, host) {
    var ts = terms(q);
    if (!ts.length && global.KBEasyView && global.KBEasyView.current() === 'easy') { host.innerHTML = '<p>Find information in this brain, or ask the assistant using the same question.</p>'; return; }
    if (!ts.length) { host.innerHTML = '<div class="ks-state"><div class="ks-state-title">Type to search</div><div>Results are labelled by the resolution that answered.</div></div>'; return; }
    var nodes = (data.brain && data.brain.nodes) || [], edges = (data.brain && data.brain.edges) || [];
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });

    var exact = nodes.map(function (n) { return [score(n.id + ' ' + (n.title || ''), ts), n]; })
      .filter(function (p) { return p[0] === ts.length; }).slice(0, MAX);
    var seen = {}; exact.forEach(function (p) { seen[p[1].id] = true; });

    var rel = [];
    exact.forEach(function (p) {
      edges.forEach(function (e) {
        var other = e.source === p[1].id ? e.target : (e.target === p[1].id ? e.source : null);
        if (other && byId[other] && !seen[other]) { seen[other] = true; rel.push([e.rel, byId[other], p[1]]); }
      });
    });

    var lex = ((data.pack && (data.pack.items || data.pack.entries || data.pack.docs || data.pack)) || []);
    if (!Array.isArray(lex)) lex = [];
    lex = lex.map(function (d) { return [score((d.title || '') + ' ' + (d.summary || '') + ' ' + (d.path || ''), ts), d]; })
      .filter(function (p) { return p[0] > 0; }).sort(function (a, b) { return b[0] - a[0]; }).slice(0, MAX);

    var out = '';
    out += '<div class="ks-section">exact (' + exact.length + ')</div><ul class="ks-list">' +
      (exact.map(function (p) { return hit('exact', p[1].title || p[1].id, p[1].text, nodeHref(p[1]), '<span class="ks-chip">' + esc(p[1].kind) + '</span>'); }).join('') || '<li class="ks-note">no node matches every term</li>') + '</ul>';
    out += '<div class="ks-section">relational (' + rel.length + ')</div><ul class="ks-list">' +
      (rel.slice(0, MAX).map(function (r) { return hit('relational', r[1].title || r[1].id, r[1].text, nodeHref(r[1]), '<span class="ks-chip">' + esc(r[0]) + ' ← ' + esc(r[2].title || r[2].id) + '</span>'); }).join('') || '<li class="ks-note">nothing one hop from an exact hit</li>') + '</ul>';
    out += '<div class="ks-section">lexical (' + lex.length + ')</div><ul class="ks-list">' +
      (lex.map(function (p) { return hit('lexical', p[1].title || p[1].path, p[1].summary, p[1].path ? '/app/reader.html?path=' + encodeURIComponent(p[1].path) : null, '<span class="ks-chip">' + p[0] + '/' + ts.length + ' terms</span>'); }).join('') || '<li class="ks-note">no document carries these terms</li>') + '</ul>';
    out += '<div class="ks-section">semantic</div><p class="ks-note">' + (data.semantic ? 'vector index present — semantic ranking is answered by the chat agent (features.semantic_search).' : 'not answered: no vector index (enable features.semantic_search and run <span class="ks-mono">make brain-embed</span>).') + '</p>';
    if (global.KBEasyView && global.KBEasyView.current() === 'easy') {
      out = '<div class="ks-section">Matching information</div><ul class="ks-list">' +
        exact.map(function (p) { return hit('', p[1].title || 'Record', p[1].text, nodeHref(p[1]), '').replace('</li>', global.KBEasyView.summaryHtml(p[1]) + '</li>'); }).join('') +
        lex.map(function (p) { return hit('', p[1].title || 'Document', p[1].summary, p[1].path ? '/app/reader.html?path=' + encodeURIComponent(p[1].path) : null, ''); }).join('') + '</ul>' +
        (!exact.length && !lex.length ? '<p>No matching information found. Try another question.</p>' : '') +
        '<button type="button" data-kb-show-advanced>Show why these results matched</button>';
    }
    host.innerHTML = out;
  }

  function mount(host) {
    host.innerHTML = '<input class="ks-input" aria-label="Find or ask about information" type="search" placeholder="Search across every resolution…" autofocus><div class="ks-results" style="margin-top:14px"></div>';
    var input = host.querySelector('input'), results = host.querySelector('.ks-results');
    results.setAttribute('aria-live', 'polite');
    var ask = document.createElement('button'); ask.type = 'button'; ask.textContent = 'Ask the assistant';
    ask.onclick = function () {
      if (!global.__kbBubble) { results.textContent = 'The assistant is unavailable here. You can still search this brain.'; return; }
      global.dispatchEvent(new CustomEvent('kb-ask', {detail:{question:input.value}}));
    };
    input.after(ask);
    global.KBShell.mount({ title: 'Search' }).then(function (cfg) {
      return Promise.all([
        fetchJson('/app/brain.json', { nodes: [], edges: [] }),
        fetchJson('/app/knowledge-pack.json', []),
        (cfg.features && cfg.features.semantic_search) ? fetch('/app/brain.vec.json', { method: 'HEAD', cache: 'no-cache' }).then(function (r) { return r.ok; }).catch(function () { return false; }) : Promise.resolve(false)
      ]);
    }).then(function (res) {
      var data = { brain: res[0], pack: res[1], semantic: res[2] };
      var q = new URLSearchParams(global.location.search).get('q') || '';
      if (q) input.value = q;
      function renderResults() {
        input.placeholder = global.KBEasyView && global.KBEasyView.current() === 'easy' ? 'Find or ask about information…' : 'Search across every resolution…';
        run(input.value, data, results);
      }
      renderResults();
      global.addEventListener('kb-view-change', renderResults);
      var t;
      input.addEventListener('input', function () { clearTimeout(t); t = setTimeout(function () { run(input.value, data, results); }, 120); });
    });
  }

  function init() { var h = document.querySelector('[data-kb-surface="search"]'); if (h) mount(h); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  global.KBSearch = { mount: mount, run: run, terms: terms };
})(window);
