/* Easy/Advanced is presentation over the same mounted components and authority.
 * It never navigates, remounts a form, or performs a write when the mode changes.
 * The shared kb_prefs cookie is a browser preference, never an authorization input.
 */
(function (global) {
  'use strict';
  var cfg = {}, mode = 'easy', mounted = false, scope = 'browser';
  var doc = global.document;
  var esc = function (value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };
  function prefs() {
    try { var match = doc.cookie.match(/(?:^|;\s*)kb_prefs=([^;]*)/); var value = match ? JSON.parse(decodeURIComponent(match[1])) : {}; return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; } catch (_) { return {}; }
  }
  function valid(value) { return value === 'easy' || value === 'advanced'; }
  function defaultMode(config) {
    var view = config.portal && config.portal.view || {};
    var scoped = (view.scopeDefaults || {})[(config.scope || {}).level];
    return valid(scoped) ? scoped : valid(view.default) ? view.default : 'easy';
  }
  function current() { return mode; }
  function setMode(value, remember) {
    if (!valid(value)) return;
    mode = value;
    if (remember) try { var valuePrefs = prefs(); var views = valuePrefs.views && typeof valuePrefs.views === 'object' && !Array.isArray(valuePrefs.views) ? valuePrefs.views : {};
      views[scope] = mode; var keys = Object.keys(views); while(keys.length > 8) { var oldest = keys.shift(); if(oldest !== scope) delete views[oldest]; } valuePrefs.views = views; doc.cookie = 'kb_prefs=' + encodeURIComponent(JSON.stringify(valuePrefs)) + ';path=/;max-age=31536000;SameSite=Lax'; } catch (_) { /* session-only when cookies are unavailable */ }
    doc.documentElement.setAttribute('data-kb-view', mode);
    var button = doc.getElementById('kb-view-toggle');
    if (button) { button.textContent = mode === 'easy' ? 'Advanced view' : 'Easy view'; button.setAttribute('aria-label', 'Switch to ' + (mode === 'easy' ? 'Advanced' : 'Easy') + ' view'); }
    var status = doc.getElementById('kb-view-status');
    if (status) status.textContent = (mode === 'easy' ? 'Easy' : 'Advanced') + ' view. Your current task is unchanged.';
    if (global.KBNav) global.KBNav.refresh();
    global.dispatchEvent(new CustomEvent('kb-view-change', {detail:{mode:mode}}));
  }
  function groups(pages) {
    var home = global.KBNav && global.KBNav.purposeHome ? global.KBNav.purposeHome() : null;
    if (home && Array.isArray(home.primary)) {
      var used = new Set(), tasks = [];
      home.primary.forEach(function (task) {
        var page = pages.find(function (p) { return p.url === task.url; });
        if (page && !used.has(page.url)) {
          used.add(page.url);
          tasks.push(Object.assign({}, page, {label:task.label,description:task.description}));
        }
      });
      var remaining = pages.filter(function (page) { return !used.has(page.url); });
      return (tasks.length ? [{group:home.title,pages:tasks}] : []).concat(remaining.length ? [{group:'More',pages:remaining}] : []);
    }
    var project = (cfg.scope || {}).level === 'project';
    var labels = {'/search/':'Ask', '/library/':'Library', '/proposals/':'Review queue', '/timeline/':'Meetings', '/federation/':'Connected brains', '/knowledge-workbench/':'Add and review', '/authoring/':'Add material'};
    if (project) labels['/status/'] = 'Status';
    var descriptions = {'/search/':'Find information or ask this brain a question.', '/library/':'Read the documents behind this brain.', '/proposals/':'Look at suggestions waiting for a curator.', '/timeline/':'See notes from past meetings.', '/federation/':'Explore the brains you are allowed to see.', '/knowledge-workbench/':'Add material and review changes with permission.', '/authoring/':'Add information using the enabled editor.', '/status/':'See where the project stands.'};
    var primary = [], more = [];
    pages.forEach(function (page) {
      var label = labels[page.url];
      (label ? primary : more).push(label ? Object.assign({}, page, {label:label,description:descriptions[page.url] || page.description}) : page);
    });
    var order = project ? ['Status','Ask','Review queue','Add and review','Add material','Library','Connected brains','Meetings'] : ['Ask','Library','Add and review','Add material','Review queue','Connected brains','Meetings'];
    primary.sort(function (a,b) { return order.indexOf(a.label)-order.indexOf(b.label); });
    return (primary.length ? [{group:'Everyday tasks',pages:primary}] : []).concat(more.length ? [{group:'More',pages:more}] : []);
  }
  // Unknown source/freshness/review/audience stays unknown. IDs are never guessed
  // into names, and a confidence score never becomes an approval.
  function summary(record) {
    record = record || {};
    var sources = record.evidence && Array.isArray(record.evidence.sources) ? record.evidence.sources.filter(function(source) { return source && typeof source === 'object'; }) : [];
    var status = record.review && record.review.state;
    var reviewed = status === 'accepted' || status === 'approved';
    var certainty = record.requiresReview || record.proposed ? 'Suggested — not yet reviewed' : reviewed ? 'Confirmed' : 'Uncertain — needs a look';
    var fresh = record.freshness;
    var checked = fresh && fresh.state !== 'unknown' && fresh.state !== 'stale' && (fresh.checkedAt || fresh.observedAt);
    var date = checked && !Number.isNaN(Date.parse(checked)) ? new Date(checked).toISOString().slice(0,10) : null;
    var evidence = sources.length ? sources.map(function (source) { return 'From: ' + (source.title || 'attached source') + (source.capturedAt ? ', added ' + String(source.capturedAt).slice(0,10) : ''); }).join('; ') : 'No source attached';
    var audience = Array.isArray(record.audienceNames) && record.audienceNames.length ? 'Visible to: ' + record.audienceNames.join(', ') : 'Audience not described for this record';
    var origin = record.originName ? 'From ' + record.originName + ' (shown here; read-only)' : record.origin || record.sourceParticipant ? 'From another brain (shown here; read-only)' : 'Shown in this brain; ownership not verified';
    return [evidence, certainty, fresh && fresh.state === 'stale' ? 'This record needs a freshness check' : date ? 'Checked ' + date : 'Freshness not tracked for this record', audience, origin];
  }
  function summaryHtml(record) {
    var sources = record && record.evidence && Array.isArray(record.evidence.sources) ? record.evidence.sources : [];
    var links = sources.filter(function (source) { return source && typeof source.path === 'string' && source.path && !/^[a-z]+:/i.test(source.path) && !source.path.startsWith('//'); }).map(function (source) {
      return '<a href="/app/reader.html?path=' + encodeURIComponent(source.path) + '">View source</a>';
    }).join(' · ');
    return '<div class="kb-easy-only kb-record-summary">' + summary(record).map(function (line) { return '<p>' + esc(line) + '</p>'; }).join('') + links + '<button type="button" data-kb-show-advanced>Show the exact record</button></div>';
  }
  function mount() {
    if (mounted) return; mounted = true;
    var css = doc.createElement('link'); css.rel = 'stylesheet'; css.href = '/app/easy-view.css'; doc.head.appendChild(css);
    var button = doc.createElement('button'); button.type = 'button'; button.id = 'kb-view-toggle'; button.onclick = function () { setMode(mode === 'easy' ? 'advanced' : 'easy', true); };
    (doc.querySelector('.topbar') || doc.querySelector('header') || doc.body).appendChild(button);
    var status = doc.createElement('span'); status.id = 'kb-view-status'; status.className = 'kb-view-sr'; status.setAttribute('aria-live','polite'); doc.body.appendChild(status);
    doc.addEventListener('click', function (event) { if (event.target.closest('[data-kb-show-advanced]')) { setMode('advanced', true); button.focus(); } });
    if (global.location.pathname === '/' || global.location.pathname === '/index.html') home();
  }
  function home() {
    if (doc.getElementById('kb-purpose-home')) return;
    var panel = doc.createElement('section'); panel.className = 'kb-easy-only kb-easy-home'; panel.setAttribute('aria-label','Everyday tasks');
    var pages = global.KBNav ? global.KBNav.visiblePages(cfg.pages || [], cfg.features) : [];
    var has = function (url) { return pages.some(function (page) { return page.url === url; }); };
    var tasks = [];
    if (has('/search/')) tasks.push('<a href="/search/">Find or ask about information</a>');
    if (has('/library/')) tasks.push('<a href="/library/">Browse the library</a>');
    if (has('/knowledge-workbench/')) tasks.push('<a href="/knowledge-workbench/">Add information or review a change</a>');
    else if (has('/authoring/')) tasks.push('<a href="/authoring/">Add information</a>');
    else tasks.push('<p>Adding information requires an enabled writing workspace. Ask this brain’s owner for access.</p>');
    if (has('/proposals/')) tasks.push('<a href="/proposals/">Review suggested connections</a>');
    if (doc.getElementById('recent-list')) tasks.push('<a href="#recent-list">See recent changes to this brain</a>');
    panel.innerHTML = '<h2>What would you like to do?</h2><div class="kb-easy-tasks">' + tasks.join('') + '</div>';
    var before = doc.querySelector('.hero') || doc.querySelector('main') || doc.querySelector('.nav-section');
    if (before) before.before(panel); else doc.body.appendChild(panel);
  }
  function configure(config, identityScope) {
    cfg = config || {};
    var nextScope = /^[a-f0-9]{64}$/.test(identityScope || '') ? identityScope : 'browser';
    if (!mounted || identityScope !== undefined && nextScope !== scope) { scope = nextScope; var saved = (prefs().views || {})[scope]; mode = valid(saved) ? saved : defaultMode(cfg); mount(); }
    setMode(mode, false);
  }
  global.KBEasyView = {configure:configure,current:current,setMode:setMode,defaultMode:defaultMode,groups:groups,summary:summary,summaryHtml:summaryHtml};
})(window);
