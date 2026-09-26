/* ── Federation surface (W1.7) ────────────────────────────────────────────────
 * Reads the brain's own manifest (app/brain-manifest.json) and, when this brain
 * is a metarepo, each child's manifest, and renders what a parent needs before
 * it federates: scope, profile composition, engine generation, populated vs
 * declared inventory, projection lag, substrate graduation, publish policy.
 * No bespoke data path: everything here is the manifest primitive, plus the
 * brain's own enrollments from client.config.json ("What I share, with whom").
 */
(function (global) {
  'use strict';
  var esc = function (s) { return global.KBShell ? global.KBShell.esc(s) : String(s == null ? '' : s); };
  var fetchJson = function (u, f) { return global.KBShell.fetchJson(u, f); };

  function chip(text, cls) { return '<span class="ks-chip ' + (cls || '') + '">' + esc(text) + '</span>'; }
  function kv(pairs) {
    return '<div class="ks-kv">' + pairs.map(function (p) {
      return '<span class="ks-k">' + esc(p[0]) + '</span><span class="ks-v">' + (p[2] ? p[1] : esc(p[1])) + '</span>';
    }).join('') + '</div>';
  }

  function lagChip(p) {
    if (!p.enabled) return chip('off', 'ks-chip-muted');
    if (!p.present) return chip('missing', 'ks-chip-bad');
    if (p.lag_commits == null) return chip('lag unknown', 'ks-chip-muted');
    if (p.lag_commits === 0) return chip('fresh', 'ks-chip-ok');
    return chip(p.lag_commits + ' commits behind', p.lag_commits > 10 ? 'ks-chip-bad' : 'ks-chip-warn');
  }

  function manifestCards(m, label) {
    var inv = m.inventory || {}, sub = m.substrate || {}, pol = m.policy || {}, eng = m.engine || {};
    var pct = inv.kinds_declared ? Math.round(100 * inv.kinds_populated / inv.kinds_declared) : 0;
    return '<div class="ks-section">' + esc(label) + '</div><div class="ks-grid">' +
      '<div class="ks-card"><h3 class="ks-card-title">Scope</h3>' + kv([
        ['level', (m.scope || {}).level || '—'], ['id', (m.scope || {}).id || '—'],
        ['parent', (m.scope || {}).parent || 'root'],
        ['peers', ((m.scope || {}).peers || []).join(', ') || '—']]) + '</div>' +
      '<div class="ks-card"><h3 class="ks-card-title">Profile & engine</h3>' + kv([
        ['composition', ((m.profile || {}).base || 'core') + ' + ' + (((m.profile || {}).overlays || []).join(' + ') || '—')],
        ['contract', 'v' + ((m.profile || {}).contract_version || '?')],
        ['brain', eng.brain_version == null ? 'none' : 'v' + eng.brain_version],
        ['schema', eng.schema_present ? 'present' : 'absent (pre-ontology)'],
        ['gates', String(eng.gates || 0)], ['template', (m.surfaces || {}).template || '—']]) + '</div>' +
      '<div class="ks-card"><h3 class="ks-card-title">Inventory</h3>' + kv([
        ['nodes / edges', inv.nodes + ' / ' + inv.edges],
        ['populated', inv.kinds_populated + ' of ' + inv.kinds_declared + ' kinds']]) +
        '<div class="ks-bar"><div class="ks-bar-fill" style="width:' + pct + '%"></div></div>' +
        (inv.unpopulated && inv.unpopulated.length ? '<p class="ks-note">unpopulated: ' + esc(inv.unpopulated.join(', ')) + '</p>' : '') + '</div>' +
      '<div class="ks-card"><h3 class="ks-card-title">Projections</h3>' +
        (m.projections || []).map(function (p) { return '<div>' + chip(p.resolution) + ' ' + lagChip(p) + '</div>'; }).join('') + '</div>' +
      '<div class="ks-card"><h3 class="ks-card-title">Substrate</h3>' + kv([
        ['tier', sub.tier || '—'], ['store', sub.store || '—'], ['blobs', sub.blobs || '—'], ['vectors', sub.vectors || '—'],
        ['deploy', ((sub.deploy || {}).target || '—') + ' [' + (((sub.deploy || {}).persistence || []).join(', ') || 'none') + ']']]) +
        (sub.graduation && sub.graduation.needed
          ? '<p class="ks-note">' + chip('graduate to ' + sub.graduation.to, 'ks-chip-warn') + ' ' + esc(sub.graduation.reason || '') + '</p>'
          : '<p class="ks-note">' + chip('within tier', 'ks-chip-ok') + ' ' + esc((sub.graduation || {}).current_nodes || 0) + ' / ' + esc((sub.graduation || {}).threshold_nodes || '—') + ' nodes</p>') + '</div>' +
      '<div class="ks-card"><h3 class="ks-card-title">Publish policy</h3>' +
        '<p class="ks-note">access gate: ' + chip(pol.access_gate ? 'on' : 'off', pol.access_gate ? 'ks-chip-ok' : 'ks-chip-muted') + '</p>' +
        '<p class="ks-note">publishes: ' + ((pol.publishes || []).map(function (k) { return chip(k, 'ks-chip-ok'); }).join('') || chip('nothing — closed by default', 'ks-chip-muted')) + '</p>' +
        '<p class="ks-note">withholds: ' + esc((pol.withholds || []).length) + ' kinds</p></div>' +
    '</div>';
  }

  // What I share with whom (#213): each signed enrollment in plain language,
  // straight from client.config.json federation.enrollments. Needs no Easy view
  // and no manifest. `signature.digest` is the sha256 of the signed fields in the
  // encoding federation_enrollment.fields_digest uses; recomputing it here tells
  // an entry edited after signing from a current one (the key stays host-side).
  function list(items) {
    return items.length < 2 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }
  var SIGNED_FIELDS = ['parent', 'publishes', 'audience', 'expires', 'withdrawn', 'issued'];
  function canon(v) {
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    if (v && typeof v === 'object') {
      return '{' + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ':' + canon(v[k]); }).join(',') + '}';
    }
    return String(JSON.stringify(v));
  }
  function current(e) {
    var subtle = global.crypto && global.crypto.subtle;
    if (!subtle || typeof TextEncoder === 'undefined') return Promise.resolve(null);
    var fields = {};
    SIGNED_FIELDS.forEach(function (k) { fields[k] = e[k]; });
    return subtle.digest('SHA-256', new TextEncoder().encode(canon(fields) + '\n')).then(function (buf) {
      var hex = Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      return hex === e.signature.digest;
    }, function () { return null; });
  }
  // Same shape federation_enrollment.when accepts: ISO 8601 date-time with a zone.
  function readable(t) {
    return typeof t === 'string' && /^\d{4}-\d{2}-\d{2}T[^Z+]*(Z|[+-]\d{2}:?\d{2})$/.test(t) && !isNaN(Date.parse(t));
  }
  function state(e) {
    if (!e.signature) return Promise.resolve(chip('not signed — this entry has no effect yet', 'ks-chip-warn'));
    var open = e.expires == null;
    if (!open && !readable(e.expires)) return Promise.resolve(chip('expiry unreadable — the parent refuses this entry; fix it and re-sign', 'ks-chip-bad'));
    return current(e).then(function (fresh) {
      if (fresh === false) return chip('edited after signing — re-sign it; the parent refuses it as it stands', 'ks-chip-bad');
      if (e.withdrawn) return chip('consent withdrawn', 'ks-chip-muted');
      if (!open && Date.parse(e.expires) <= Date.now()) {
        return chip('renewal needed — expired; the parent keeps what it holds but takes nothing new until you re-sign with a later expiry', 'ks-chip-warn');
      }
      return fresh ? chip('signed', 'ks-chip-ok') : chip('signed (not checked in this browser)', 'ks-chip-warn');
    });
  }
  function sharing(config) {
    var rows = (((config || {}).federation || {}).enrollments || []).filter(function (e) { return e && typeof e === 'object'; });
    return Promise.all(rows.map(state)).then(function (states) {
      var body = rows.length ? rows.map(function (e, i) {
        var p = e.publishes || {}, what = [];
        (p.kinds || []).forEach(function (k) { what.push('every ' + esc(String(k).replace(/-/g, ' '))); });
        (p.rules || []).forEach(function (r) { what.push('each ' + esc(String(r.kind).replace(/-/g, ' ')) + ' labelled “' + esc(r.label) + '”'); });
        if ((p.records || []).length) what.push((p.records.length === 1 ? 'one chosen record' : p.records.length + ' chosen records') + ' (' + esc(p.records.join(', ')) + ')');
        var sentence = e.withdrawn ? 'You share nothing with ' + esc(e.parent) + ' any more; it removes what it held from you.'
          : 'You share ' + (list(what) || 'nothing') + ' with ' + esc(e.parent) + ', seen there by ' +
            esc((e.audience || []).join(', ') || 'no one') +
            (e.expires == null ? ', with no expiry.' : ', until ' + esc(String(e.expires).slice(0, 10)) + '.');
        return '<p class="ks-note">' + states[i] + ' ' + sentence + '</p>';
      }).join('') : '<p class="ks-note">You share nothing with any parent brain. To share, add an entry under federation.enrollments and sign it.</p>';
      return '<div class="ks-section">What I share, with whom</div><div class="ks-card">' + body +
        '<p class="ks-note">Kinds you withhold and restricted files never leave, whatever is listed here.</p></div>';
    });
  }
  // The card goes in its own element so it renders whatever else the page shows.
  function sharingInto(host, config) {
    var el = document.createElement('div');
    host.appendChild(el);
    return sharing(config).then(function (html) { el.innerHTML = html; });
  }

  function mount(host) {
    var cfg;
    global.KBShell.mount({ title: 'Federation' }).then(function (config) {
      cfg = config;
      // The shared shell returns {} when configuration is unavailable. That is
      // not evidence of a legacy selection and must never trigger static reads.
      if (!config || !global.KBNav || !String(global.KBNav.brainName(config)).trim() || !Array.isArray(config.pages) ||
          (Object.prototype.hasOwnProperty.call(config, 'portal') &&
            (!config.portal || typeof config.portal !== 'object' || Array.isArray(config.portal)))) {
        host.innerHTML = '<p class="ks-state">Navigation configuration unavailable.</p>';
        return false;
      }
      if (config.portal && Object.prototype.hasOwnProperty.call(config.portal, 'federationNavigation')) {
        var subtitle = document.querySelector('.page-subtitle');
        if (subtitle) subtitle.textContent = 'Explore visible brains, their source identities, relationships and alternate paths.';
        var nav = document.createElement('div');
        nav.innerHTML = '<p class="ks-state">Loading navigation…</p>';
        host.innerHTML = '';
        host.appendChild(nav);
        sharingInto(host, config);
        var css = document.createElement('link');
        css.rel = 'stylesheet'; css.href = '/app/federation-navigation.css'; document.head.appendChild(css);
        var script = document.createElement('script');
        script.src = '/app/federation-navigation.js';
        script.onload = function () {
          if (global.KBFederationNavigation && typeof global.KBFederationNavigation.mount === 'function') {
            global.KBFederationNavigation.mount(nav, config.portal.federationNavigation);
          } else nav.innerHTML = '<p class="ks-state">Navigation unavailable.</p>';
        };
        script.onerror = function () { nav.innerHTML = '<p class="ks-state">Navigation unavailable.</p>'; };
        document.head.appendChild(script);
        return false;
      }
      return fetchJson('/app/brain-manifest.json', null);
    }).then(function (m) {
      if (m === false) return;
      if (!m) {
        host.innerHTML = '<div class="ks-state"><div class="ks-state-title">No manifest</div><div>Run <span class="ks-mono">make manifest</span> to compile this brain\'s self-description.</div></div>';
        return sharingInto(host, cfg);
      }
      var children = (m.federation || {}).children || [];
      host.innerHTML = manifestCards(m, 'This brain — ' + ((m.identity || {}).name || (m.identity || {}).id || ''));
      sharingInto(host, cfg);
      if (!children.length) {
        host.insertAdjacentHTML('beforeend', '<p class="ks-note">No child brains declared (federation.children). A metarepo lists its sub-brains there; each child\'s manifest renders below.</p>');
        return;
      }
      return Promise.all(children.map(function (c) {
        return fetchJson('/' + String(c).replace(/^\/|\/$/g, '') + '/app/brain-manifest.json', null).then(function (cm) { return [c, cm]; });
      })).then(function (pairs) {
        pairs.forEach(function (pr) {
          host.insertAdjacentHTML('beforeend', pr[1]
            ? manifestCards(pr[1], 'Child — ' + pr[0])
            : '<div class="ks-section">Child — ' + esc(pr[0]) + '</div><p class="ks-note">' + chip('no manifest', 'ks-chip-bad') + ' this child predates the manifest; its generation is unknown until it runs <span class="ks-mono">make manifest</span>.</p>');
        });
      });
    });
  }

  function init() { var h = document.querySelector('[data-kb-surface="federation"]'); if (h) mount(h); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  global.KBFederation = { mount: mount, manifestCards: manifestCards, sharing: sharing };
})(window);
