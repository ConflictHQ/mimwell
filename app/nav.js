/* ── Shared portal navigation ─────────────────────────────────────────────────
 * One source of truth for the grouped top-nav (every page) and the grouped home
 * nav-card grid (index.html only). Pages used to each carry an identical
 * `buildNav`; this module replaces that copy so grouping + active-state logic
 * can't drift between pages.
 *
 * Pages model: each entry in client.config.json `pages[]` may carry an optional
 * "group" (e.g. "Knowledge", "Plan & Delivery", "Intelligence", "Reference").
 * Ungrouped pages fall under DEFAULT_GROUP. Original page order is preserved
 * within each group, and groups appear in first-seen order.
 *
 * Exposes a global `KBNav` so plain <script src> pages can use it without
 * modules. Every method is null-safe and renders clean empty states.
 *
 * Feature-flag awareness (#17/#39): topnav/navGrid filter flag-gated pages out of
 * EVERY page's nav, not just the home grid. A page whose url maps to a disabled
 * optional surface (FLAG_BY_URL below) is dropped — hidden, not a broken link —
 * before grouping. Surfaces with no flag entry are always shown. The map is the
 * single place that ties an optional page to its toggle, so #39 stays the only
 * owner of which pages appear.
 *
 * Where features come from (single source of truth): callers MAY pass
 * opts.features (cfg.features) and it wins when present. But to stop the gate from
 * silently depending on each of ~25 pages remembering to forward opts, KBNav owns
 * the features source itself: it caches a features object (settable via
 * KBNav.config(cfg)/KBNav.setFeatures(...)) and, on first nav build, lazily fetches
 * /client.config.json to populate that cache, then re-runs the last build with the
 * resolved flags. So a flag-gated page is hidden consistently across the whole
 * portal even on pages that call topnav(el, pages) with no opts.
 *
 * Owner co-brand (#47): this module also owns the owner/co-brand mark that the
 * page shells used to paste in as an inline wordmark SVG. Shells now carry an
 * empty `data-kb-owner-mark="<px height>"` slot and KBNav fills it from
 * client.config.json `branding.owner` — see the seam block below.
 *
 * Mobile nav (#39): past ~20 entries the wrapped top-nav stops being usable on
 * small screens, so topnav() also wires a hamburger toggle. On wide viewports the
 * grouped bar shows as before; under the CSS breakpoint the bar collapses into a
 * drawer opened by the .topnav-toggle button (rendered into el's parent once).
 * The toggle is injected only when a host button/CSS hook exists, so pages that
 * have not opted in are unchanged.
 * ──────────────────────────────────────────────────────────────────────────── */
(function (global) {
  'use strict';

  var DEFAULT_GROUP = 'More';

  // Optional surfaces gated behind a feature flag. Key = page url (as registered
  // in client.config.json pages[]), value = the features.* flag that must be
  // truthy for the page to appear. Pages absent from this map are always shown.
  // #39 owns this map alongside the pages array it mirrors.
  var FLAG_BY_URL = {
    '/authoring/': 'authoring'
  };

  // Module-cached feature flags — the fallback features source so gating does not
  // depend on every page forwarding opts.features (see header). null = not yet
  // known; once set (explicitly via KBNav.config/setFeatures, or by the lazy
  // config fetch below) it is used whenever a caller omits opts.features.
  var cachedFeatures = null;
  var configFetchStarted = false;
  var configGeneration = 0;
  // Page-sets (#203): a registered page may carry `requires: <overlay>`; it is
  // part of the portal only when the config's profile selects that overlay.
  // undefined = profile not known yet (nothing filtered); null = the config
  // declares no overlays, the legacy shape, so every page stays registered;
  // otherwise the selected base plus overlays.
  var cachedPageSets;
  // The last topnav/navGrid build, replayed once cachedFeatures resolves so a
  // nav rendered before the flags were known re-filters with them.
  var lastBuild = null;
  var builds = [];
  var easyReady = null;
  function loadEasy(cfg) {
    if (!global.document || !global.document.createElement) return Promise.resolve();
    if (global.KBEasyView) return (easyReady || Promise.resolve()).then(function () { global.KBEasyView.configure(cfg); });
    if (!easyReady) easyReady = new Promise(function (resolve) {
      var script = global.document.createElement("script"); script.src = "/app/easy-view.js";
      script.onload = function () {
        var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 3000);
        global.fetch('/api/view-preference-scope', {cache:'no-store',credentials:'same-origin',signal:controller.signal})
          .then(function (response) { return response.ok ? response.json() : {}; }).catch(function () { return {}; })
          .then(function (identity) { clearTimeout(timeout); if (global.KBEasyView) global.KBEasyView.configure(cfg, identity.scope || null); resolve(); });
      };
      script.onerror = resolve; global.document.head.appendChild(script);
    });
    return easyReady;
  }

  /* ── Owner / co-brand seam (#47) ────────────────────────────────────────────
   * The portal chrome co-brands TWO parties: the CLIENT (branding.heroMark, the
   * engagement's own mark, rendered in the home hero) and the OWNER (whoever
   * runs the engagement, rendered as the topbar wordmark and the footer mark).
   * Owner chrome used to be an inline wordmark SVG pasted into every page shell,
   * so re-branding a portal meant editing ~23 files. It now comes from config:
   * page shells carry an EMPTY slot (`data-kb-owner-mark="<px height>"`) and
   * this module fills it from `branding.owner`.
   *
   * `branding.owner` accepts either shape:
   *   "Acme Corp"                              -> owner name only (legacy)
   *   { name, mark, markDark }                 -> name + artwork
   * `mark`/`markDark` are image URLs; when both are given they render as a
   * theme-aware pair (markDark on dark chrome, mark on light) via the same
   * theme.css logo-on-* classes the hero mark uses.
   *
   * DEFAULT: with no artwork configured the slot renders the owner NAME as a
   * plain text wordmark. That keeps an unbranded install looking finished while
   * baking no company's artwork into the engine.
   */
  var DEFAULT_OWNER_NAME = 'ACME';
  var DEFAULT_MARK_HEIGHT = 24;

  // Resolve branding.owner (either shape) into { name, mark, markDark }.
  // `owner: ""` / `owner: null` mean "no owner brand" and are honored — the
  // footer expression has always treated an explicit empty owner as a drop.
  function ownerBrand(branding) {
    var b = branding || {};
    var o = b.owner;
    var out = { name: DEFAULT_OWNER_NAME, mark: '', markDark: '' };
    if (o === null) out.name = '';
    else if (typeof o === 'string') out.name = o;
    else if (o && typeof o === 'object') {
      out.name = (o.name === undefined || o.name === null) ? DEFAULT_OWNER_NAME : String(o.name);
      out.mark = o.mark || '';
      out.markDark = o.markDark || '';
    }
    // Legacy co-brand (pre-#47): portals that only set the client heroMark got
    // it in the topbar slot. Honored when no owner artwork is configured so
    // those portals keep rendering a mark rather than falling back to text.
    if (!out.mark && b.heroMark && out.name) {
      out.mark = b.heroMark;
      out.markDark = b.heroMarkDark || '';
    }
    return out;
  }

  function ownerName(branding) { return ownerBrand(branding).name; }

  /* Purpose-neutral owner seam (#206, Phase 1: alias). brainName/brainOwnerName
   * are NOT the co-brand seam above — ownerBrand/ownerName answer "who runs
   * this portal" (branding.owner, defaults to 'ACME'); brainOwnerName
   * answers "who does this brain belong to" (brain.owner: a person or an
   * organization). brain.name / brain.owner are canonical; client.name is a
   * read alias for one release (2026-09-22 decision) so an unmigrated config —
   * or the browser fetch of client.config.json, which never runs through
   * scripts/config.py's resolver — still resolves. Every page reads through
   * these two functions instead of poking cfg.client.name itself. */
  function brainName(cfg) {
    var c = cfg || {};
    var brain = c.brain || {};
    var client = c.client || {};
    return brain.name || client.name || client.shortName || '';
  }

  // Short label for headers and footers: brain.shortName, else the
  // client.shortName alias, else the full brain name.
  function brainShortName(cfg) {
    var c = cfg || {};
    return (c.brain && c.brain.shortName) || (c.client && c.client.shortName) || brainName(cfg);
  }

  function brainOwnerName(cfg) {
    var owner = (cfg && cfg.brain && cfg.brain.owner) || null;
    if (owner && typeof owner === 'object' && owner.name) return owner.name;
    return brainName(cfg);
  }

  // What the brain is for: brain.purpose, else the client.engagement alias.
  function brainPurpose(cfg) {
    var c = cfg || {};
    return (c.brain && c.brain.purpose) || (c.client && c.client.engagement) || '';
  }

  /* Home hero copy (#362): the brain's name and purpose through the seam above,
   * its kind from scope.level, and the portal template's front door. Engagement
   * wording belongs to a project-scope brain only: a company, topic or personal
   * brain on the engagement template gets its kind's framing instead. The
   * co-brand (the portal owner beside the brain in the footer and stat) is
   * dropped when the portal owner is the brain's own party, and only an
   * engagement eyebrow reads "<portal owner> for <brain>" (never "ACME for
   * ACME"); other kinds name the brain's owner. `tpl` is the selected
   * portal template, or null before it loads. */
  var KIND_LABELS = { company: 'Company Brain', workspace: 'Topic Brain', person: 'Personal Brain' };
  function heroCopy(cfg, tpl) {
    var c = cfg || {};
    var name = brainName(c), short = brainShortName(c), holder = brainOwnerName(c);
    var runner = ownerName(c.branding);
    var level = String((c.scope && c.scope.level) || 'project');
    var project = level === 'project';
    var same = function (a, b) { return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase(); };
    var ownParty = [name, short, holder].some(function (s) { return same(s, runner); });
    var coBrand = runner && !ownParty ? runner : '';
    var kind = KIND_LABELS[level] || (level.charAt(0).toUpperCase() + level.slice(1) + ' Brain');
    var front = (tpl && tpl.frontDoor) || {};
    var engagementTemplate = !tpl || tpl.id === 'engagement';
    var eyebrow, desc;
    if (project) {
      eyebrow = name ? (coBrand ? coBrand + ' for ' + name : name + ' Engagement')
        : (runner ? runner + ' Engagement' : 'Engagement');
      desc = !engagementTemplate && front.desc ? front.desc : name
        ? 'A living project command center for the ' + name + ' engagement. Direct access to the ' +
          'engagement knowledge base and interactive knowledge graph — continuously updated as work progresses.'
        : '';
    } else {
      eyebrow = holder && !same(holder, name) && !same(holder, short) ? holder : kind;
      desc = !engagementTemplate && front.desc ? front.desc
        : 'The living ' + kind.toLowerCase() + (name ? ' of ' + name : '') + ': its knowledge, decisions ' +
          'and the documents behind them, continuously updated.';
    }
    var label = engagementTemplate ? (project ? front.eyebrow || 'Engagement Portal' : kind) : front.eyebrow || kind;
    return { eyebrow: eyebrow, title: short, subtitle: brainPurpose(c), purpose: brainPurpose(c),
             desc: desc, label: label, coBrand: coBrand };
  }

  // Markup for one owner mark slot: the configured artwork when there is any,
  // otherwise a text wordmark of the owner name (and nothing at all when the
  // engagement has explicitly cleared the owner brand).
  function ownerMarkHtml(branding, height) {
    var o = ownerBrand(branding);
    var h = height > 0 ? height : DEFAULT_MARK_HEIGHT;
    if (o.mark) {
      var alt = o.name || '';
      var mk = function (src, cls) {
        return '<img class="owner-mark' + (cls ? ' ' + cls : '') + '" src="' + esc(src) +
          '" alt="' + esc(alt) + '" height="' + h + '">';
      };
      return o.markDark
        ? mk(o.markDark, 'logo-on-dark') + mk(o.mark, 'logo-on-light')
        : mk(o.mark, '');
    }
    if (!o.name) return '';
    return '<span class="owner-wordmark" style="font-size:' +
      Math.max(10, Math.round(h * 0.62)) + 'px">' + esc(o.name) + '</span>';
  }

  // Fill every owner-brand slot on the page. Idempotent and order-independent:
  // both callers (a page's own config fetch and the lazy fetch below) read the
  // same config, so re-running simply re-renders the same markup.
  function applyOwnerBrand(branding) {
    var doc = global.document;
    if (!doc || !doc.querySelectorAll) return;
    injectNavCss();
    Array.prototype.forEach.call(doc.querySelectorAll('[data-kb-owner-mark]'), function (el) {
      var h = parseInt(el.getAttribute('data-kb-owner-mark'), 10);
      el.innerHTML = ownerMarkHtml(branding, h);
    });
  }

  // Auto-fill on load so every page that loads nav.js gets owner chrome with no
  // per-page code. Pages that already fetch the config may also call
  // KBNav.applyOwnerBrand(cfg.branding) directly. On an unreachable config the
  // default (text wordmark) still renders rather than leaving an empty slot.
  var ownerFetchStarted = false;
  function ensureOwnerBrand() {
    var doc = global.document;
    if (ownerFetchStarted || !doc || !doc.querySelector) return;
    if (!doc.querySelector('[data-kb-owner-mark]')) return;
    ownerFetchStarted = true;
    var generation = configGeneration;
    if (typeof global.fetch !== 'function') { applyOwnerBrand(null); return; }
    global.fetch('/client.config.json', { cache: 'no-cache' })
      .then(function (r) { return r.json(); })
      .then(function (cfg) { if (generation !== configGeneration) return;
        applyOwnerBrand(cfg && cfg.branding);
        setProfile(cfg && cfg.profile);
        loadExperience(cfg);
        loadEasy(cfg); })
      .catch(function () { applyOwnerBrand(null); });
  }

  function setFeatures(features) {
    if (features && typeof features === 'object') {
      cachedFeatures = features;
      replayLastBuild();
    }
  }

  function setProfile(profile) {
    var overlays = profile && Array.isArray(profile.overlays) ? profile.overlays : [];
    cachedPageSets = overlays.length ? [String(profile.base || 'core')].concat(overlays.map(String)) : null;
    replayLastBuild();
  }
  // A page outside every page-set, or in a selected one, is registered.
  function registered(p) {
    return !p || !p.requires || !cachedPageSets || cachedPageSets.indexOf(String(p.requires)) >= 0;
  }

  // Portal template (W1.10): the presentation profile. A template ORDERS and
  // GROUPS the pages an instance registers; it never invents one. Held here so
  // groupPages() — the single grouping hook both topnav and navGrid use — can
  // consult it, and so switching `portal.template` in config changes the nav
  // and the front door with no page edits.
  var experienceSelected = false;
  var experienceStarted = false;
  function loadExperience(cfg) {
    var selected = cfg && cfg.portal && cfg.portal.experience;
    experienceSelected = !!(selected && ['1.0','1.1'].includes(selected.protocolVersion));
    if (!experienceSelected) return;
    cachedTemplate = null;
    if (experienceStarted || !global.document || !global.document.createElement) return;
    experienceStarted = true;
    function failed() {
      var el = global.document.createElement('p'); el.setAttribute('role', 'status');
      el.id = 'kb-experience-status'; el.textContent = 'Presentation unavailable; standard navigation remains available.';
      global.document.body.prepend(el);
    }
    if (global.KBExperience) { global.KBExperience.mount(cfg); return; }
    var script = global.document.createElement('script'); script.src = '/app/experience.js';
    script.onload = function () { if (global.KBExperience) global.KBExperience.mount(cfg); else failed(); };
    script.onerror = failed; global.document.head.appendChild(script);
  }
  var cachedTemplate = null;
  var selectedTemplate = null;
  var cachedPurposeHome = null;
  var registryPromise = null;
  var selectionKey = null;
  var selectionGeneration = 0;
  var selectionPromise = null;
  var SCOPE_TEMPLATES = {company: 'company', project: 'engagement', topic: 'topic', person: 'personal'};
  function scopeTemplateId(cfg) {
    var scope = cfg && cfg.scope && cfg.scope.level;
    if (scope === 'workspace' && cfg.profile && Array.isArray(cfg.profile.overlays) && cfg.profile.overlays.indexOf('topic') >= 0) return 'topic';
    return Object.prototype.hasOwnProperty.call(SCOPE_TEMPLATES, scope) ? SCOPE_TEMPLATES[scope] : null;
  }
  function resolveTemplateId(cfg) {
    var explicit = cfg && cfg.portal && cfg.portal.template;
    return typeof explicit === 'string' && explicit && explicit !== 'auto' ? explicit : (scopeTemplateId(cfg) || 'wiki');
  }
  function setTemplate(tpl) {
    if (tpl && typeof tpl === 'object' && Array.isArray(tpl.groups)) {
      // Invalidate a pending registry selection when an embedder supplies its own.
      selectionGeneration++;
      selectionKey = null;
      selectedTemplate = tpl;
      cachedTemplate = experienceSelected ? null : tpl;
      cachedPurposeHome = tpl.home || null;
      replayLastBuild();
    }
  }
  function loadRegistry() {
    if (!registryPromise) {
      registryPromise = typeof global.fetch !== 'function' ? Promise.resolve([]) :
        global.fetch('/app/portal-templates.json', {cache: 'no-cache'})
          .then(function (r) { if (r.ok === false) throw new Error('Template registry unavailable'); return r.json(); })
          .then(function (data) { return data && Array.isArray(data.templates) ? data.templates : []; })
          .catch(function () { return []; });
    }
    return registryPromise;
  }
  function selectPortalTemplate(cfg) {
    var id = resolveTemplateId(cfg), scopeId = scopeTemplateId(cfg);
    var experience = cfg && cfg.portal && cfg.portal.experience;
    var hasExperience = !!(experience && ['1.0', '1.1'].includes(experience.protocolVersion));
    var key = JSON.stringify([id, scopeId, hasExperience]);
    if (key === selectionKey) return selectionPromise;
    selectionKey = key;
    var generation = ++selectionGeneration;
    cachedTemplate = selectedTemplate = cachedPurposeHome = null;
    selectionPromise = loadRegistry().then(function (list) {
      if (generation !== selectionGeneration) return null;
      selectedTemplate = list.find(function (tpl) { return tpl && tpl.id === id; }) || null;
      var scopeTemplate = list.find(function (tpl) { return tpl && tpl.id === scopeId; });
      cachedPurposeHome = (selectedTemplate && selectedTemplate.home) || (scopeTemplate && scopeTemplate.home) || null;
      cachedTemplate = !hasExperience && selectedTemplate && Array.isArray(selectedTemplate.groups) ? selectedTemplate : null;
      replayLastBuild();
      if (global.dispatchEvent && typeof global.CustomEvent === 'function') {
        global.dispatchEvent(new global.CustomEvent('kb:portal-template', {detail: {template: selectedTemplate, home: cachedPurposeHome}}));
      }
      return selectedTemplate;
    });
    return selectionPromise;
  }
  function loadPortalTemplate(cfg) { return selectPortalTemplate(cfg); }
  function loadPurposeHome(cfg) {
    var pending = selectPortalTemplate(cfg), generation = selectionGeneration;
    return pending.then(function () { return generation === selectionGeneration ? cachedPurposeHome : null; });
  }
  function template() { return cachedTemplate; }
  function purposeHome() { return cachedPurposeHome; }
  function configure(cfg) {
    configGeneration++;
    setFeatures(cfg && cfg.features);
    applyOwnerBrand(cfg && cfg.branding);
    setProfile(cfg && cfg.profile);
    loadExperience(cfg);
    loadEasy(cfg);
    return loadPortalTemplate(cfg);
  }

  // Lazily fetch /client.config.json once to learn features.*, so pages that call
  // topnav(el, pages) with no opts still get correct flag gating. No-op without
  // fetch (older hosts) or once features are already known.
  function ensureConfigFetched() {
    if (configFetchStarted || cachedFeatures || typeof global.fetch !== 'function') return;
    configFetchStarted = true;
    var generation = configGeneration;
    global.fetch('/client.config.json', { cache: 'no-cache' })
      .then(function (r) { return r.json(); })
      .then(function (cfg) {
        if (generation === configGeneration) configure(cfg);
      })
      .catch(function () { /* leave gating open if config is unreachable */ });
  }

  function replayLastBuild() {
    builds.slice().forEach(function (build) {
      if (build.kind === 'topnav') topnav(build.el, build.pages, build.opts);
      else navGrid(build.el, build.pages, build.opts);
    });
  }

  // Resolve the effective features for a build: an explicit opts.features wins;
  // otherwise fall back to the module cache (and kick off the lazy fetch that
  // populates it for next time / a replay).
  function effectiveFeatures(opts) {
    var explicit = opts && opts.features;
    if (explicit) return explicit;
    ensureConfigFetched();
    return cachedFeatures;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Nav presentation, injected once from here so every page that loads nav.js
  // gets it with no per-page CSS edit. Colors come from the shared --kb-* theme
  // seam (light/dark aware) with neutral fallbacks — never hardcoded brand
  // values. Desktop (> breakpoint): groups render as TIERED CASCADING MENUS —
  // the bar carries one button per group and the group's page links live in a
  // dropdown panel that opens on hover, focus-within, or click (.open, for
  // touch). Mobile: the bar collapses into a slide-in drawer where every menu
  // is expanded flat (group name as a section heading), same as before.
  function injectNavCss() {
    var doc = global.document;
    if (!doc || !doc.head || doc.getElementById('kb-nav-css')) return;
    var css =
      /* ── Owner co-brand slots (#47) ── artwork or a text wordmark, both
         driven by branding.owner; colors come from the shared --kb-* seam so a
         rebrand recolors them, never a baked brand value. ── */
      'img.owner-mark{display:block;width:auto;}' +
      '.owner-wordmark{display:inline-block;line-height:1;white-space:nowrap;' +
        'font-family:var(--kb-font-heading,inherit);letter-spacing:.16em;' +
        'text-transform:uppercase;color:var(--kb-text,inherit);}' +
      '.footer-mark{display:inline-flex;align-items:center;line-height:0;opacity:.45;}' +
      /* ── Desktop tiers: group button + dropdown panel ── */
      '.topnav-group{position:relative;display:inline-flex;align-items:center;}' +
      '.topnav-group-btn{display:inline-flex;align-items:center;gap:5px;background:none;' +
        'border:none;cursor:pointer;padding:6px 10px;color:var(--kb-muted,inherit);' +
        'font:inherit;letter-spacing:inherit;text-transform:inherit;white-space:nowrap;}' +
      '.topnav-group-btn::after{content:"";width:6px;height:6px;margin-top:-3px;' +
        'border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;' +
        'transform:rotate(45deg);opacity:.55;transition:transform .15s ease;}' +
      '.topnav-group-btn:hover,.topnav-group.open>.topnav-group-btn,' +
        '.topnav-group.has-active>.topnav-group-btn{color:var(--kb-text,#fff);}' +
      '.topnav-menu{position:absolute;top:100%;left:0;min-width:200px;display:none;' +
        'flex-direction:column;padding:6px;margin-top:4px;z-index:250;' +
        'background:var(--kb-surface,var(--kb-bg,#1c1c1c));' +
        'border:1px solid var(--kb-border,rgba(128,128,128,.3));border-radius:6px;' +
        'box-shadow:0 10px 28px rgba(0,0,0,.35);}' +
      /* keep an invisible hover bridge so the pointer can cross the 4px gap */
      '.topnav-menu::before{content:"";position:absolute;top:-5px;left:0;right:0;height:5px;}' +
      '@media (hover:hover) and (min-width:921px){' +
        '.topnav-group:hover>.topnav-menu,.topnav-group:focus-within>.topnav-menu{display:flex;}' +
        '.topnav-group:hover>.topnav-group-btn::after,' +
          '.topnav-group:focus-within>.topnav-group-btn::after{transform:rotate(225deg);margin-top:3px;}' +
      '}' +
      '@media (min-width:921px){' +
        '.topnav-group.open>.topnav-menu{display:flex;}' +
        '.topnav-group.open>.topnav-group-btn::after{transform:rotate(225deg);margin-top:3px;}' +
        '.topnav-menu a{display:block;padding:8px 12px;border-radius:4px;white-space:nowrap;}' +
        '.topnav-menu a:hover{background:var(--kb-border,rgba(128,128,128,.18));}' +
        /* group labels never render as inline text on desktop anymore */
        '.topnav-group-label{display:none;}' +
      '}' +
      '.topnav-toggle{display:none;align-items:center;justify-content:center;' +
        'width:36px;height:32px;background:none;border:1px solid var(--kb-border,rgba(128,128,128,.3));' +
        'border-radius:4px;cursor:pointer;padding:0;color:var(--kb-text,#fff);}' +
      '.topnav-toggle-bars,.topnav-toggle-bars::before,.topnav-toggle-bars::after{' +
        'content:"";display:block;width:16px;height:2px;background:currentColor;' +
        'border-radius:2px;transition:transform .18s ease,opacity .18s ease;}' +
      '.topnav-toggle-bars{position:relative;}' +
      '.topnav-toggle-bars::before{position:absolute;top:-5px;left:0;}' +
      '.topnav-toggle-bars::after{position:absolute;top:5px;left:0;}' +
      'body.nav-open .topnav-toggle-bars{background:transparent;}' +
      'body.nav-open .topnav-toggle-bars::before{transform:translateY(5px) rotate(45deg);}' +
      'body.nav-open .topnav-toggle-bars::after{transform:translateY(-5px) rotate(-45deg);}' +
      '@media (max-width:920px){' +
        '.topnav-toggle{display:inline-flex;}' +
        '.topnav{position:fixed;top:54px;right:0;bottom:0;width:min(82vw,320px);' +
          'flex-direction:column;align-items:stretch;gap:2px;overflow-y:auto;' +
          'padding:14px 14px 28px;background:var(--kb-bg,#0B1619);' +
          'border-left:1px solid var(--kb-border,rgba(128,128,128,.3));' +
          'transform:translateX(100%);transition:transform .22s ease;z-index:300;}' +
        'body.nav-open .topnav{transform:translateX(0);}' +
        '.topnav-group{flex-direction:column;align-items:stretch;gap:2px;}' +
        '.topnav-group+.topnav-group{margin-left:0;padding-left:0;border-left:none;' +
          'margin-top:10px;padding-top:10px;border-top:1px solid var(--kb-border,rgba(128,128,128,.25));}' +
        /* in the drawer the tiers flatten: label as heading, menu always expanded */
        '.topnav-group-btn{display:none;}' +
        '.topnav-group-label{display:block;padding:2px 8px;}' +
        '.topnav-menu{position:static;display:flex;flex-direction:column;min-width:0;' +
          'padding:0;margin:0;background:none;border:none;box-shadow:none;}' +
        '.topnav-menu::before{display:none;}' +
        '.topnav a{display:block;padding:9px 10px;font-size:11px;}' +
      '}';
    var style = doc.createElement('style');
    style.id = 'kb-nav-css';
    style.textContent = css;
    doc.head.appendChild(style);
  }

  // Drop pages whose page-set is not selected (see setProfile), then pages whose
  // feature flag is off. `features` is cfg.features (or absent — then no flag
  // filters). A page is flag-hidden only when it has a FLAG_BY_URL entry AND
  // that flag is explicitly falsy in the provided features object.
  function visiblePages(pages, features) {
    return (pages || []).filter(function (p) {
      if (!registered(p)) return false;
      var flag = features && p && FLAG_BY_URL[normUrl(p.url)];
      if (!flag) return true;
      return !!features[flag];
    });
  }

  // A template may narrow the registered pages by page-set: `excludes` drops
  // the listed sets, `includes` (when given) keeps only the listed sets. Pages
  // outside every page-set are always kept, and neither can add a page.
  function templateAdmits(p, tpl) {
    var set = p && p.requires;
    if (!set || !tpl) return true;
    if (Array.isArray(tpl.excludes) && tpl.excludes.indexOf(set) >= 0) return false;
    return !Array.isArray(tpl.includes) || tpl.includes.indexOf(set) >= 0;
  }
  function homePages(pages, features) {
    return visiblePages(pages, features || cachedFeatures).filter(function (p) { return templateAdmits(p, selectedTemplate); });
  }

  // Normalize a url for "current page" comparison: drop a trailing index.html so
  // "/roadmap/" and "/roadmap/index.html" compare equal.
  function normUrl(u) { return String(u || '').replace(/index\.html$/, ''); }

  // Absolute http(s) URLs in pages[] point outside this portal (a sibling brain
  // in a federated setup, or any external destination). They open in a new tab
  // (target=_blank rel=noopener) and carry an outbound ↗ affordance so they are
  // distinguishable from internal pages. Detection is by URL shape — no config.
  function isExternal(u) { return /^https?:\/\//i.test(String(u || '')); }

  // Group pages in first-seen group order, preserving page order within a group.
  // Returns [{ group: <name>, pages: [<page>, ...] }, ...].
  function groupPages(pages) {
    pages = (pages || []).filter(function (p) { return templateAdmits(p, cachedTemplate); });
    if (!experienceSelected && global.KBEasyView && global.KBEasyView.current() === 'easy') return global.KBEasyView.groups(pages);
    var order = [];
    var byGroup = {};
    var placed = {};
    // Template first: its groups, in its order, holding only the pages that are
    // actually registered (a template is a view, never a source of pages).
    if (cachedTemplate) {
      var byUrl = {};
      (pages || []).forEach(function (p) { if (p && p.url) byUrl[normUrl(p.url)] = p; });
      cachedTemplate.groups.forEach(function (grp) {
        var name = String(grp.group || DEFAULT_GROUP);
        (grp.pages || []).forEach(function (url) {
          var p = byUrl[normUrl(url)];
          if (!p || placed[normUrl(url)]) return;
          if (!byGroup[name]) { byGroup[name] = []; order.push(name); }
          byGroup[name].push(p);
          placed[normUrl(url)] = true;
        });
      });
    }
    // Then every registered page the template did not place, under its own group.
    (pages || []).forEach(function (p) {
      if (!p || (p.url && placed[normUrl(p.url)])) return;
      var g = (p && p.group) ? String(p.group) : DEFAULT_GROUP;
      if (!byGroup[g]) { byGroup[g] = []; order.push(g); }
      byGroup[g].push(p);
    });
    return order.map(function (g) { return { group: g, pages: byGroup[g] }; });
  }

  // Render the tiered top-nav into `el`. Home ("/") is skipped — the logo links
  // home. Tier one is one button per group; tier two is the group's page links
  // in a cascading dropdown (hover/focus opens on desktop, click toggles .open
  // for touch — see wireMenus; in the mobile drawer every menu renders expanded
  // under its label). The page matching the current location is marked .active
  // and its group gets .has-active so the active trail reads from the bar.
  // `opts.features` (cfg.features) hides flag-gated pages.
  function topnav(el, pages, opts) {
    if (!el) return;
    lastBuild = { kind: 'topnav', el: el, pages: pages, opts: opts };
    builds = builds.filter(function (b) { return b.el !== el; }); builds.push(lastBuild);
    var features = effectiveFeatures(opts);
    var here = normUrl(global.location.pathname);
    var visible = visiblePages(pages, features).filter(function (p) { return p && p.url !== '/'; });
    var groups = groupPages(visible);
    if (!groups.length) { el.innerHTML = ''; return; }
    el.innerHTML = groups.map(function (grp) {
      var hasActive = false;
      var links = grp.pages.map(function (p) {
        var active = normUrl(p.url) === here;
        hasActive = hasActive || active;
        var ext = isExternal(p.url); // link out to a sibling portal / external site
        return '<a href="' + esc(p.url) + '"' + (active ? ' class="active"' : '') +
          (ext ? ' target="_blank" rel="noopener"' : '') + '>' +
          esc(p.label || p.url) + (ext ? ' ↗' : '') + '</a>';
      }).join('');
      return '<span class="topnav-group' + (hasActive ? ' has-active' : '') + '">' +
        '<button type="button" class="topnav-group-btn" aria-haspopup="true" aria-expanded="false">' +
          esc(grp.group) + '</button>' +
        '<span class="topnav-group-label">' + esc(grp.group) + '</span>' +
        '<span class="topnav-menu">' + links + '</span>' +
      '</span>';
    }).join('');
    wireMenus(el);
    wireMobileNav(el);
  }

  // Dropdown behavior for the tier-one group buttons: click toggles the menu
  // (touch and keyboard; hover/focus-within already opens it via CSS on
  // pointer devices), only one menu open at a time, outside click or Escape
  // closes. Idempotent per render — topnav() replaces el's children, so
  // per-button listeners die with the old DOM; the document-level closers are
  // registered once.
  function wireMenus(el) {
    var doc = global.document;
    if (!doc || !el) return;
    function closeAll() {
      Array.prototype.forEach.call(el.querySelectorAll('.topnav-group.open'), function (g) {
        g.classList.remove('open');
        var b = g.querySelector('.topnav-group-btn');
        if (b) b.setAttribute('aria-expanded', 'false');
      });
    }
    Array.prototype.forEach.call(el.querySelectorAll('.topnav-group-btn'), function (btn) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var grp = btn.parentNode;
        var open = grp.classList.contains('open');
        closeAll();
        if (!open) {
          grp.classList.add('open');
          btn.setAttribute('aria-expanded', 'true');
        }
      });
    });
    if (!el._kbMenusWired) {
      el._kbMenusWired = true;
      doc.addEventListener('click', function (e) {
        if (!el.contains(e.target)) closeAll();
      });
      doc.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeAll();
      });
      // A tap on a menu link should not leave a stale open menu behind on
      // same-page (hash) navigations.
      el.addEventListener('click', function (e) {
        if (e.target && e.target.tagName === 'A') closeAll();
      });
    }
  }

  // Mobile nav: inject (once) a hamburger button as the previous sibling of the
  // top-nav and toggle a `nav-open` class on <body>. The drawer presentation is
  // pure CSS, self-injected by injectNavCss() so every page that loads nav.js
  // gets it with no per-page edit; this function owns only the button + open/close
  // state. On desktop the button is hidden and the bar renders as before. A click
  // on any nav link, an outside click, or Escape closes the drawer. Idempotent:
  // re-running topnav() does not stack buttons or listeners.
  function wireMobileNav(el) {
    var doc = global.document;
    if (!doc || !el || !el.parentNode) return;
    injectNavCss();
    var host = el.parentNode;
    var btn = host.querySelector('.topnav-toggle');
    if (!btn) {
      btn = doc.createElement('button');
      btn.type = 'button';
      btn.className = 'topnav-toggle';
      btn.setAttribute('aria-label', 'Menu');
      btn.setAttribute('aria-expanded', 'false');
      btn.innerHTML = '<span class="topnav-toggle-bars" aria-hidden="true"></span>';
      host.insertBefore(btn, el);
      var setOpen = function (open) {
        doc.body.classList.toggle('nav-open', open);
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      };
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        setOpen(!doc.body.classList.contains('nav-open'));
      });
      // Close on link tap or any outside click.
      el.addEventListener('click', function (e) {
        if (e.target && e.target.tagName === 'A') setOpen(false);
      });
      doc.addEventListener('click', function (e) {
        if (!doc.body.classList.contains('nav-open')) return;
        if (host.contains(e.target)) return;
        setOpen(false);
      });
      doc.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') setOpen(false);
      });
    }
  }

  // Render the grouped home nav-card grid into `el`. Each group becomes a labeled
  // band of cards. Card type-badge colors cycle by global card index so adjacent
  // cards stay visually distinct; the first card keeps the .primary accent.
  function navGrid(el, pages, opts) {
    if (!el) return;
    lastBuild = { kind: 'navGrid', el: el, pages: pages, opts: opts };
    builds = builds.filter(function (b) { return b.el !== el; }); builds.push(lastBuild);
    var list = visiblePages(pages, effectiveFeatures(opts));
    if (!list.length) {
      el.innerHTML = '<a class="nav-card" style="cursor:default"><div class="nav-title" style="color:var(--dim)">No sections configured</div></a>';
      return;
    }
    var groups = groupPages(list);
    var i = 0;
    el.innerHTML = groups.map(function (grp) {
      var cards = grp.pages.map(function (p) {
        var cls = i === 0 ? 'nav-card primary' : 'nav-card';
        var badge = 'nt-' + (i % 6);
        i++;
        var ext = isExternal(p.url); // sibling portal / external site
        return '<a class="' + cls + '" href="' + esc(p.url) + '"' +
          (ext ? ' target="_blank" rel="noopener"' : '') + '>' +
          '<div class="nav-card-top">' +
            '<span class="nav-type-badge ' + badge + '">' + esc(p.label || p.url) + '</span>' +
            '<span class="nav-arrow">' + (ext ? '↗' : '→') + '</span>' +
          '</div>' +
          '<div class="nav-title">' + esc(p.label || p.url) + '</div>' +
          '<div class="nav-desc">' + esc(p.description || '') + '</div>' +
        '</a>';
      }).join('');
      if (grp.group === 'More' && global.KBEasyView && global.KBEasyView.current() === 'easy') return '<details class="nav-group"><summary>More views</summary><div class="nav-group-grid">' + cards + '</div></details>';
      return '<div class="nav-group">' +
        '<div class="nav-group-label">' + esc(grp.group) + '</div>' +
        '<div class="nav-group-grid">' + cards + '</div>' +
      '</div>';
    }).join('');
  }

  global.KBNav = {
    DEFAULT_GROUP: DEFAULT_GROUP,
    DEFAULT_OWNER_NAME: DEFAULT_OWNER_NAME,
    FLAG_BY_URL: FLAG_BY_URL,
    esc: esc,
    // Owner / co-brand seam (#47): pages read the owner NAME for their footer,
    // hero eyebrow, and co-brand stat; the mark slots fill themselves.
    ownerBrand: ownerBrand,
    ownerName: ownerName,
    ownerMarkHtml: ownerMarkHtml,
    applyOwnerBrand: applyOwnerBrand,
    // Purpose-neutral owner seam (#206): who the BRAIN belongs to, not who
    // runs the portal (that's ownerBrand/ownerName above).
    brainName: brainName,
    brainShortName: brainShortName,
    brainOwnerName: brainOwnerName,
    brainPurpose: brainPurpose,
    heroCopy: heroCopy,
    groupPages: groupPages,
    visiblePages: visiblePages,
    topnav: topnav,
    navGrid: navGrid,
    // Seed the features source explicitly (KBNav.config(cfg) or
    // KBNav.setFeatures(cfg.features)); otherwise it is fetched lazily.
    config: configure,
    resolveTemplateId: resolveTemplateId,
    loadPortalTemplate: loadPortalTemplate,
    loadPurposeHome: loadPurposeHome,
    purposeHome: purposeHome,
    homePages: homePages,
    easyReady: function () { return easyReady || Promise.resolve(); },
    refresh: replayLastBuild,
    setFeatures: setFeatures,
    // Page-set seam (#203): seed the selected overlays from cfg.profile.
    setProfile: setProfile,
    // Portal template seam (W1.10): set directly (tests, embedders) or learned
    // lazily from config; read back for front-door framing.
    setTemplate: setTemplate,
    template: template
  };

  // Owner chrome does not wait for a nav build — a page with a brand slot and no
  // top-nav (the deck viewer) still gets its mark.
  if (global.document) {
    if (global.document.readyState === 'loading') {
      global.document.addEventListener('DOMContentLoaded', ensureOwnerBrand);
    } else {
      ensureOwnerBrand();
    }
  }
})(typeof window !== 'undefined' ? window : this);
