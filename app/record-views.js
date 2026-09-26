/* Selected record IA. Operates only on an already authorized response. No store,
 * federation discovery, writer, expression execution or persistent record cache. */
(function (global) {
  'use strict';
  var MAX_ROWS = 10000, MAX_BYTES = 4194304;
  function fail() { throw new Error('Record view unavailable'); }
  function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function field(r, name) { return own(r, name) ? r[name] : null; }
  function scalar(x) { return x === null || typeof x === 'string' || typeof x === 'boolean' || typeof x === 'number' && Number.isFinite(x) && Math.abs(x) <= Number.MAX_SAFE_INTEGER; }
  function token(x) { if (!scalar(x)) fail(); return JSON.stringify(x); }
  function compare(a, b) {
    if (a === b) return 0;
    if (a === null) return 1;
    if (b === null) return -1;
    if (typeof a !== typeof b) return typeof a < typeof b ? -1 : 1;
    return a < b ? -1 : 1;
  }
  function values(r, name) {
    var v = field(r, name);
    if (Array.isArray(v)) {
      if (v.length > 1000 || !v.every(function (x) { return typeof x === 'string'; })) fail();
      return v.length ? Array.from(new Set(v)) : [null];
    }
    if (!scalar(v)) fail();
    return [v];
  }
  function matches(r, predicate) {
    var v = field(r, predicate.field), p = predicate.value;
    switch (predicate.op) {
      case 'eq': return v === p;
      case 'contains': return Array.isArray(v) && v.includes(p);
      case 'in': return p.includes(v);
      case 'exists': return (v !== null) === p;
      default: return fail();
    }
  }
  function keyFor(view, row) {
    var parts = view.key.map(function (f) {
      var v = field(row, f);
      if (!scalar(v) || v === null || v === '' || typeof v === 'string' && v.length > 300) fail();
      return v;
    });
    return JSON.stringify([view.kind, view.artifact, parts]);
  }
  function fields(kind) {
    if (!Array.isArray(kind.fields)) fail();
    var result = new Map();
    kind.fields.forEach(function (f) { if (!f || result.has(f.name)) fail(); result.set(f.name, f); });
    return result;
  }
  function exact(o, keys) {
    if (!o || typeof o !== 'object' || Array.isArray(o) || Object.keys(o).length !== keys.length || !keys.every(function (k) { return own(o, k); })) fail();
  }
  function array(a, max, min) { if (!Array.isArray(a) || a.length > max || a.length < (min || 0)) fail(); }
  function unique(a) { if (new Set(a).size !== a.length) fail(); }
  function text(s, limit) { if (typeof s !== 'string' || !s.length || s.length > limit) fail(); }
  function validateView(view, kind) {
    exact(view, ['id','label','kind','artifact','key','scope','facets','groupBy','order','search','layout','density','responsive','pageSize','breadcrumbs','defaultSelection']);
    text(view.id, 80); if (!/^[a-z][a-z0-9.-]*$/.test(view.id)) fail(); text(view.label, 160);
    if (!kind || !kind.renderable || view.kind !== kind.id || view.artifact !== kind.artifact || !/^app\/[A-Za-z0-9_-]+\.json$/.test(kind.artifact) || typeof kind.records !== 'string') fail();
    var fs = fields(kind);
    function type(name) { if (typeof name !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(name) || !fs.has(name)) fail(); return fs.get(name); }
    function simple(name) { if (!['string','number','integer','boolean'].includes(type(name).type)) fail(); }
    function searchable(name) { var f = type(name); if (!(f.type === 'array' && f.items === 'string')) simple(name); }
    function typed(value, name) {
      var t = type(name).type;
      return value === null || t === 'string' && typeof value === 'string' && value.length <= 300 || t === 'boolean' && typeof value === 'boolean' || t === 'number' && typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER || t === 'integer' && Number.isSafeInteger(value);
    }
    array(view.key, 3, 1); unique(view.key); view.key.forEach(simple);
    array(view.scope, 16); view.scope.forEach(function (p) {
      exact(p, ['field','op','value']); var t = type(p.field), v = p.value;
      if (p.op === 'eq') { simple(p.field); if (!typed(v, p.field)) fail(); }
      else if (p.op === 'in') { simple(p.field); array(v, 32, 1); if (!v.every(function (x) { return typed(x, p.field); })) fail(); }
      else if (p.op === 'contains') { if (t.type !== 'array' || t.items !== 'string' || typeof v !== 'string' || v.length > 300) fail(); }
      else if (p.op === 'exists') { searchable(p.field); if (typeof v !== 'boolean') fail(); }
      else fail();
    });
    array(view.facets, 8); unique(view.facets.map(function (f) { return f.field; }));
    view.facets.forEach(function (f) { exact(f, ['field','label']); searchable(f.field); text(f.label, 160); });
    if (view.groupBy !== null) searchable(view.groupBy);
    array(view.order, 4); view.order.forEach(function (o) { exact(o, ['field','direction']); simple(o.field); if (!['asc','desc'].includes(o.direction)) fail(); });
    array(view.search, 12); unique(view.search); view.search.forEach(searchable);
    if (!['list','detail','workbench'].includes(view.layout) || !['comfortable','compact'].includes(view.density) || !['auto','stacked'].includes(view.responsive) || !Number.isInteger(view.pageSize) || view.pageSize < 1 || view.pageSize > 100 || typeof view.breadcrumbs !== 'boolean' || !['none','first'].includes(view.defaultSelection)) fail();
    return view;
  }
  function pageConfig(config, kinds, pathname, hostKinds) {
    exact(config, ['protocolVersion','pages']); if (config.protocolVersion !== '1.0') fail(); array(config.pages, 32, 0);
    unique(config.pages.map(function (p) { return p.url; }));
    var canonical = decodeURIComponent(pathname).replace(/index\.html$/, '');
    if (!canonical.endsWith('/')) canonical += '/';
    var page = config.pages.find(function (p) { return p.url === canonical; });
    if (!page) {
      // Unknown aliases of a selected kind must not silently widen its scope.
      if (config.pages.some(function (p) { return Array.isArray(p.views) && p.views.some(function (v) { return hostKinds.includes(v.kind); }); })) fail();
      return null;
    }
    exact(page, ['url','entry','pinned','views']); array(page.views, 20, 1); array(page.pinned, 20); unique(page.pinned);
    var byId = new Map(); kinds.forEach(function (k) { if (byId.has(k.id)) fail(); byId.set(k.id, k); });
    page.views.forEach(function (view) {
      var kind = byId.get(view.kind);
      validateView(view, kind);
      if (!hostKinds.includes(view.kind) || '/' + kind.page.replace(/^\/+|\/+$/g, '') + '/' !== page.url) fail();
    });
    var ids = page.views.map(function (v) { return v.id; }); unique(ids);
    if (!ids.includes(page.entry) || !page.pinned.every(function (id) { return ids.includes(id); })) fail();
    return page;
  }
  function project(view, kind, rows, state) {
    validateView(view, kind); array(rows, MAX_ROWS);
    var seen = new Set(), base = [];
    // Source-level duplicates are ambiguous even if a presentation filter would
    // leave one visible. Never let filtering choose an identity collision winner.
    rows.forEach(function (row) {
      if (!row || typeof row !== 'object' || Array.isArray(row)) fail();
      var key = keyFor(view, row); if (seen.has(key)) fail(); seen.add(key);
      if (view.scope.every(function (p) { return matches(row, p); })) base.push({key:key, row:row});
    });
    var query = String(state.query || '').trim().toLowerCase(); if (query.length > 300) fail();
    var selected = state.facets || {}; if (!selected || typeof selected !== 'object' || Array.isArray(selected)) fail();
    var allowed = view.facets.map(function (f) { return f.field; });
    if (Object.keys(selected).some(function (f) { return !allowed.includes(f) || !scalar(selected[f]); })) fail();
    function filtered(item, skip) {
      return (!query || view.search.some(function (f) { return values(item.row, f).some(function (v) { return v !== null && String(v).toLowerCase().includes(query); }); })) &&
        Object.keys(selected).every(function (f) { return f === skip || values(item.row, f).some(function (v) { return v === selected[f]; }); });
    }
    var facets = view.facets.map(function (f) {
      var options = new Map();
      base.forEach(function (item) { if (filtered(item, f.field)) values(item.row, f.field).forEach(function (v) {
        var k = token(v), o = options.get(k) || {value:v, count:0}; o.count++; options.set(k, o);
        if (options.size > 200) fail();
      }); });
      return {field:f.field, label:f.label, options:Array.from(options.values()).sort(function (a,b) { return compare(a.value,b.value); })};
    });
    var matched = base.filter(function (item) { return filtered(item, null); });
    matched.sort(function (a,b) {
      for (var o of view.order) {
        var av = field(a.row,o.field), bv = field(b.row,o.field); if (!scalar(av) || !scalar(bv)) fail();
        var c = compare(av,bv); if (c) return c * (o.direction === 'desc' ? -1 : 1);
      }
      return compare(a.key,b.key);
    });
    var pageCount = Math.max(1, Math.ceil(matched.length / view.pageSize));
    var page = Number.isInteger(state.page) ? Math.min(pageCount, Math.max(1,state.page)) : 1;
    var selection = state.record || (view.defaultSelection === 'first' && matched.length ? matched[0].key : null);
    var detail = matched.find(function (item) { return item.key === selection; }) || null;
    var visible = matched.slice((page - 1) * view.pageSize, page * view.pageSize), groups = new Map();
    var memberships = 0;
    visible.forEach(function (item) {
      var labels = view.groupBy ? values(item.row,view.groupBy) : [null];
      labels.forEach(function (v) {
        var k = token(v), g = groups.get(k) || {value:v, items:[]};
        if (++memberships > 1000 || !groups.has(k) && groups.size >= 200) fail();
        g.items.push(item); groups.set(k,g);
      });
    });
    return {count:matched.length, page:page, pages:pageCount, facets:facets, groups:Array.from(groups.values()).sort(function (a,b) { return compare(a.value,b.value); }), detail:detail, selectionUnavailable:!!state.record && state.record !== '~none' && !detail};
  }
  function readState(hash, page) {
    if (hash.length > 8192) fail();
    var q = new URLSearchParams(hash.replace(/^#/,''));
    for (var key of q.keys()) { if (!['view','q','facets','record','page'].includes(key) || q.getAll(key).length !== 1) fail(); }
    var view = q.get('view') || page.entry;
    if (!page.views.some(function (v) { return v.id === view; })) fail();
    var facets = JSON.parse(q.get('facets') || '{}'), index = Number(q.get('page') || 1);
    if (!Number.isSafeInteger(index) || index < 1) fail();
    return {view:view, query:q.get('q') || '', facets:facets, record:q.get('record') || null, page:index};
  }
  function stateHash(state) {
    var params = new URLSearchParams(); params.set('view', state.view);
    if (state.query) params.set('q',state.query);
    if (Object.keys(state.facets).length) params.set('facets',JSON.stringify(state.facets));
    if (state.record) params.set('record',state.record);
    if (state.page > 1) params.set('page',String(state.page));
    var result = '#' + params.toString(); if (result.length > 8192) fail(); return result;
  }
  async function fetchCollection(kind, signal) {
    if (!/^app\/[A-Za-z0-9_-]+\.json$/.test(kind.artifact)) fail();
    var response = await fetch('/' + kind.artifact, {cache:'no-store',redirect:'error',signal:signal});
    if (!response.ok || !response.body || Number(response.headers.get('content-length')) > MAX_BYTES) fail();
    var reader = response.body.getReader(), parts = [], size = 0;
    while (true) { var chunk = await reader.read(); if (chunk.done) break; size += chunk.value.byteLength; if (size > MAX_BYTES) { await reader.cancel(); fail(); } parts.push(chunk.value); }
    var all = new Uint8Array(size), offset = 0; parts.forEach(function (part) { all.set(part,offset); offset += part.length; });
    var data = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));
    if (!data || !own(data,kind.records)) fail(); array(data[kind.records],MAX_ROWS);
    return data[kind.records]; // Deliberately ignore any artifact-wide count.
  }
  async function verifyDescriptors(page, kinds, pins) {
    if (!pins || !global.crypto || !global.crypto.subtle) fail();
    function canonical(value) {
      if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
      if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(function (k) { return JSON.stringify(k) + ':' + canonical(value[k]); }).join(',') + '}';
      return JSON.stringify(value);
    }
    for (var id of new Set(page.views.map(function (v) { return v.kind; }))) {
      var kind = kinds.find(function (k) { return k.id === id; });
      if (!kind || !own(pins,id)) fail();
      var digest = await global.crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(kind)));
      var actual = Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2,'0'); }).join('');
      if (actual !== pins[id]) fail();
    }
  }
  function mount(host, page, kinds, renderRecord) {
    var state, rows = null, sourceKind = null, controller = null, generation = 0, focusRequest = null, lastSelection = null;
    var byId = new Map(kinds.map(function (k) { return [k.id,k]; }));
    function node(tag, text, attrs) {
      var el = document.createElement(tag); if (text !== null) el.textContent = text;
      Object.keys(attrs || {}).forEach(function (key) { el.setAttribute(key,attrs[key]); }); return el;
    }
    function button(text, action) { var el = node('button',text,{type:'button'}); el.addEventListener('click',action); return el; }
    function failure() {
      generation++; if (controller) controller.abort();
      focusRequest = null; lastSelection = null; rows = null; sourceKind = null; host.replaceChildren(node('p','Record view unavailable. Check the selected configuration or retry when its source is available.',{role:'status'}));
      host.appendChild(button('Retry',function () { load(); }));
    }
    function view() { return page.views.find(function (v) { return v.id === state.view; }); }
    function navigate(delta, replace) {
      try {
        if (own(delta,'view') && delta.view !== state.view) focusRequest = {type:'view',id:delta.view};
        else if (delta.record && delta.record !== '~none') focusRequest = {type:'detail'};
        else if (delta.record === '~none') focusRequest = {type:'record',id:lastSelection};
        else if (own(delta,'page') && !own(delta,'query') && !own(delta,'facets')) focusRequest = {type:'results'};
        var next = Object.assign({},state,delta), hash = stateHash(next);
        if (replace) global.history.replaceState(null,'',hash); else global.history.pushState(null,'',hash);
        state = next;
        if (sourceKind !== view().kind || !rows) load(); else render();
      } catch (_) { failure(); }
    }
    function link(label, delta) {
      var el = node('a',label,{href:stateHash(Object.assign({},state,delta))});
      el.addEventListener('click',function (event) {
        if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault(); navigate(delta);
      }); return el;
    }
    function render() {
      try {
        var v = view(), kind = byId.get(v.kind), result = project(v,kind,rows,state);
        lastSelection = result.detail ? result.detail.key : null;
        host.dataset.recordLayout = v.layout; host.dataset.recordDensity = v.density; host.dataset.recordResponsive = v.responsive;
        var focused = document.activeElement, focusName = focused && focused.getAttribute('data-record-control');
        var start = focused && focused.selectionStart;
        host.replaceChildren();
        var navigation = node('nav',null,{'aria-label':'Record views',class:'rv-views'});
        var ids = page.pinned.concat(page.views.map(function (x) { return x.id; }).filter(function (id) { return !page.pinned.includes(id); }));
        ids.forEach(function (id) {
          var item = page.views.find(function (x) { return x.id === id; });
          var el = link(item.label,{view:id,query:'',facets:{},record:null,page:1});
          el.setAttribute('data-view-id',id);
          if (id === state.view) el.setAttribute('aria-current','page');
          if (page.pinned.includes(id)) { el.setAttribute('data-pinned','true'); el.setAttribute('aria-label',item.label); el.title = 'Pinned view'; }
          navigation.appendChild(el);
        }); host.appendChild(navigation);
        if (v.breadcrumbs) {
          var crumbs = node('nav',null,{'aria-label':'Record breadcrumbs'});
          crumbs.appendChild(link(v.label,{record:'~none'}));
          if (result.detail) crumbs.appendChild(node('span',' / ' + String(result.detail.row[kind.display.title] || '(untitled)')));
          host.appendChild(crumbs);
        }
        var controls = node('div',null,{class:'rv-controls'});
        if (v.search.length) {
          var label = node('label','Search records '), search = node('input',null,{type:'search','aria-label':'Search records','data-record-control':'query',maxlength:'300'});
          search.value = state.query; search.addEventListener('input',function () { navigate({query:search.value,page:1,record:null},true); }); label.appendChild(search); controls.appendChild(label);
        }
        result.facets.forEach(function (facet) {
          var label = node('label',facet.label + ' '), select = node('select',null,{'aria-label':facet.label,'data-record-control':facet.field});
          select.appendChild(node('option','All',{value:''}));
          facet.options.forEach(function (option) { select.appendChild(node('option',(option.value === null ? '(Missing)' : String(option.value)) + ' (' + option.count + ')',{value:token(option.value)})); });
          if (own(state.facets,facet.field)) {
            var selected = token(state.facets[facet.field]);
            if (!Array.from(select.options).some(function (o) { return o.value === selected; })) select.appendChild(node('option','Selected value unavailable',{value:selected}));
            select.value = selected;
          }
          select.addEventListener('change',function () {
            var next = Object.assign({},state.facets); if (select.value === '') delete next[facet.field]; else next[facet.field] = JSON.parse(select.value);
            navigate({facets:next,page:1,record:null});
          }); label.appendChild(select); controls.appendChild(label);
        });
        controls.appendChild(button('Clear filters',function () { navigate({query:'',facets:{},page:1,record:null}); }));
        controls.appendChild(button('Refresh records',function () { focusRequest = {type:'results'}; load(); })); host.appendChild(controls);
        host.appendChild(node('p',result.count + ' matching records',{role:'status',class:'rv-count'}));
        var workspace = node('div',null,{class:'rv-workspace'}), listPane = node('section',null,{'aria-label':'Matching records',class:'rv-master',tabindex:'-1'});
        if (!result.count) listPane.appendChild(node('p','No matching records.'));
        result.groups.forEach(function (group) {
          if (v.groupBy) listPane.appendChild(node('h2',group.value === null ? '(Missing)' : String(group.value)));
          var list = node('ul',null,{class:'rv-list'});
          group.items.forEach(function (item) {
            var li = node('li',null), a = link(String(item.row[kind.display.title] || '(untitled)'),{record:item.key});
            a.setAttribute('data-record-key',item.key);
            if (result.detail && result.detail.key === item.key) a.setAttribute('aria-current','true');
            li.appendChild(a);
            // Lists remain summaries. The shared schema renderer owns detail.
            (kind.display.status || []).forEach(function (f) { if (scalar(item.row[f]) && item.row[f] != null) li.appendChild(node('span',' · ' + item.row[f])); });
            list.appendChild(li);
          }); listPane.appendChild(list);
        });
        var pager = node('nav',null,{'aria-label':'Record pagination'});
        var prev = button('Previous',function () { navigate({page:result.page-1}); }), next = button('Next',function () { navigate({page:result.page+1}); });
        prev.disabled = result.page <= 1; next.disabled = result.page >= result.pages;
        pager.append(prev,node('span',' Page ' + result.page + ' of ' + result.pages + ' '),next); listPane.appendChild(pager);
        var detail = node('section',null,{'aria-label':'Record detail',class:'rv-detail',tabindex:'-1'});
        if (result.detail) {
          detail.appendChild(link('Back to results',{record:'~none'}));
          var records = node('ul',null,{class:'rv-record'}); records.innerHTML = renderRecord(kind,result.detail.row); detail.appendChild(records);
        } else detail.appendChild(node('p',result.selectionUnavailable ? 'Selected record unavailable in this view.' : 'Select a record to inspect.'));
        if (v.layout !== 'detail' || !result.detail) workspace.appendChild(listPane);
        if (v.layout === 'workbench' || result.detail || result.selectionUnavailable) workspace.appendChild(detail);
        host.appendChild(workspace);
        if (focusRequest) {
          var request = focusRequest; focusRequest = null;
          var target = request.type === 'detail' ? host.querySelector('.rv-detail') : request.type === 'results' ? host.querySelector('.rv-master') :
            Array.from(host.querySelectorAll(request.type === 'view' ? '[data-view-id]' : '[data-record-key]')).find(function (el) {
              return el.getAttribute(request.type === 'view' ? 'data-view-id' : 'data-record-key') === request.id;
            });
          if (target) target.focus(); else { var fallback = host.querySelector('.rv-master, .rv-detail'); if (fallback) fallback.focus(); }
        } else if (focusName) {
          var restore = Array.from(host.querySelectorAll('[data-record-control]')).find(function (el) { return el.getAttribute('data-record-control') === focusName; });
          if (restore) { restore.focus(); if (start !== null && typeof restore.setSelectionRange === 'function' && restore.type === 'search') restore.setSelectionRange(start,start); }
        }
      } catch (_) { failure(); }
    }
    async function load() {
      var ticket = ++generation; if (controller) controller.abort(); controller = new AbortController();
      var currentController = controller; rows = null; sourceKind = null;
      host.replaceChildren(node('p','Loading selected records…',{role:'status'}));
      var timeout = setTimeout(function () { currentController.abort(); },15000);
      try {
        state = readState(global.location.hash,page); var kind = byId.get(view().kind);
        var loaded = await fetchCollection(kind,currentController.signal);
        if (ticket !== generation || document.hidden) return;
        rows = loaded; sourceKind = kind.id; render();
      } catch (_) { if (ticket === generation) failure(); }
      finally { clearTimeout(timeout); }
    }
    function history() {
      try { var next = readState(global.location.hash,page);
        if (rows && stateHash(next) === stateHash(state)) return;
        if (next.view !== state.view) focusRequest = {type:'view',id:next.view};
        else if (next.record !== state.record) focusRequest = next.record && next.record !== '~none' ? {type:'detail'} : {type:'record',id:lastSelection};
        else if (stateHash(next) !== stateHash(state)) focusRequest = {type:'results'};
        state = next; if (!rows || sourceKind !== view().kind) load(); else render(); }
      catch (_) { failure(); }
    }
    global.addEventListener('popstate',history); global.addEventListener('hashchange',history);
    document.addEventListener('visibilitychange',function () {
      if (document.hidden) { generation++; if (controller) controller.abort(); rows = null; sourceKind = null; host.replaceChildren(node('p','Records paused while this page is hidden.',{role:'status'})); }
      else load();
    });
    load();
  }
  global.KBRecordViews = {verifyDescriptors:verifyDescriptors,mount:mount,validateView:validateView,pageConfig:pageConfig,project:project,keyFor:keyFor,readState:readState,stateHash:stateHash,fetchCollection:fetchCollection};
})(typeof window === 'undefined' ? globalThis : window);
