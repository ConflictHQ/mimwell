/* ──────────────────────────────────────────────────────────────────────────
   Shared theme controller for the client portal template.

   - On load, sets <html data-theme="…"> from the kb_prefs cookie, falling back
     to the OS preference (prefers-color-scheme), then the config default. The
     worker reads the same cookie and stamps data-theme before paint, so this is
     usually a no-op confirmation; it still applies when the worker is absent.
   - Injects an accessible sun/moon toggle button into the page's top header.
   - On click, flips the theme and persists the choice to the cookie (so the
     worker can read it server-side — see docs/primitives/theming.md).

   Settings persist in a single shared cookie (kb_prefs, URL-encoded JSON) that
   bubble.js also writes (chat answer-mode); it carries no PII.

   Paired with app/theme.css, which defines the light + dark palettes keyed off
   the data-theme attribute. Drop both into any page:
     <link rel="stylesheet" href="/app/theme.css">
     <script src="/app/theme.js" defer></script>
   No dependencies; safe to load before or after the page's own scripts.
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  var COOKIE = 'kb_prefs';
  var root = document.documentElement;

  // Shared cookie prefs (theme + chat mode + future settings). Read returns the
  // parsed object; write merges one key and re-serializes so theme.js and
  // bubble.js don't clobber each other's settings.
  function readPrefs() {
    try {
      var m = document.cookie.match(/(?:^|;\s*)kb_prefs=([^;]*)/);
      if (!m) return {};
      var o = JSON.parse(decodeURIComponent(m[1]));
      return (o && typeof o === 'object') ? o : {};
    } catch (e) { return {}; }
  }

  function writePref(key, value) {
    try {
      var prefs = readPrefs();
      prefs[key] = value;
      // 1 year, root path, Lax — readable by the worker; no PII.
      document.cookie = COOKIE + '=' +
        encodeURIComponent(JSON.stringify(prefs)) +
        ';path=/;max-age=31536000;SameSite=Lax';
    } catch (e) { /* cookies disabled */ }
  }

  function osPref() {
    return (window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: light)').matches)
      ? 'light' : 'dark';
  }

  function stored() {
    var v = readPrefs().theme;
    return (v === 'light' || v === 'dark') ? v : null;
  }

  function current() {
    var t = root.getAttribute('data-theme');
    return (t === 'light' || t === 'dark') ? t : osPref();
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme);
  }

  function persist(theme) {
    writePref('theme', theme);
  }

  // ── Text-size scaler ───────────────────────────────────────────────────────
  // An accessibility zoom for readers who want larger type. Pages size most
  // chrome in px, so a root font-size bump wouldn't reach them; CSS `zoom` on
  // the root scales the whole layout uniformly, which is what "zoom in a bit"
  // means here. Steps cycle 100 -> 115 -> 130 -> 100 and persist in kb_prefs
  // (same cookie as the theme choice), applied pre-paint below to avoid flash.
  var SCALES = [1, 1.15, 1.3];

  function storedScale() {
    var v = readPrefs().fontScale;
    return (typeof v === 'number' && SCALES.indexOf(v) !== -1) ? v : 1;
  }

  function applyScale(scale) {
    root.style.zoom = scale === 1 ? '' : String(scale);
  }

  function scaleLabel(scale) {
    return 'Text size ' + Math.round(scale * 100) + '% — click to enlarge';
  }


  // ── Brand font loader ──────────────────────────────────────────────────────
  // Pages ship placeholder font <link>s; the real brand faces live in
  // branding.fonts (client.config.json). Fetch the config once, extract the
  // first concrete family from each stack, and inject a single Google Fonts
  // stylesheet so every page renders in the declared brand fonts. Generic
  // families (system-ui, sans-serif, …) and already-loaded families are
  // skipped; failures are silent (pages keep their placeholder/system faces).
  var GENERIC = ['system-ui', 'sans-serif', 'serif', 'monospace', 'ui-monospace',
                 '-apple-system', 'blinkmacsystemfont', 'segoe ui', 'cursive', 'fantasy'];
  var WEIGHTS = { heading: '400;500;600;700', body: '400;500;600', mono: '400;500' };

  function firstFamily(stack) {
    if (!stack) return null;
    var first = String(stack).split(',')[0].trim().replace(/^['"]|['"]$/g, '');
    if (!first || GENERIC.indexOf(first.toLowerCase()) !== -1) return null;
    return first;
  }

  function loadBrandFonts() {
    if (document.querySelector('link[data-kb-brand-fonts]')) return; // idempotent
    fetch('/client.config.json', { cache: 'no-cache' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) {
        var experience = cfg && cfg.portal && cfg.portal.experience;
        if (experience && ['1.0','1.1'].includes(experience.protocolVersion) &&
            (experience.fontMode === 'system' || experience.fontMode === 'local')) return;
        var fonts = cfg && cfg.branding && cfg.branding.fonts;
        if (!fonts) return;
        var loaded = Array.prototype.map.call(
          document.querySelectorAll('link[href*="fonts.googleapis.com"]'),
          function (l) { return l.href; }).join(' ');
        var parts = [];
        Object.keys(WEIGHTS).forEach(function (role) {
          var fam = firstFamily(fonts[role]);
          if (!fam) return;
          var enc = fam.replace(/ /g, '+');
          if (loaded.indexOf('family=' + enc) !== -1) return; // page already loads it
          var spec = 'family=' + enc + ':wght@' + WEIGHTS[role];
          if (parts.indexOf(spec) === -1) parts.push(spec);
        });
        if (!parts.length) return;
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.setAttribute('data-kb-brand-fonts', '');
        link.href = 'https://fonts.googleapis.com/css2?' + parts.join('&') + '&display=swap';
        document.head.appendChild(link);
      })
      .catch(function () { /* offline / no config — placeholder faces stand */ });
  }
  loadBrandFonts();

  // Set the initial theme + text size as early as possible to avoid a flash.
  apply(stored() || osPref());
  applyScale(storedScale());

  // Icons: sun (shown in dark mode → click for light), moon (shown in light).
  var SUN =
    '<svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="4"/>' +
    '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41' +
    'M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>';
  var MOON =
    '<svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  function label(theme) {
    return theme === 'dark'
      ? 'Switch to light theme'
      : 'Switch to dark theme';
  }

  function build() {
    if (document.querySelector('.theme-toggle')) return; // idempotent

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'theme-toggle';
    btn.innerHTML = SUN + MOON;
    btn.setAttribute('aria-label', label(current()));
    btn.setAttribute('title', label(current()));

    btn.addEventListener('click', function () {
      var next = current() === 'dark' ? 'light' : 'dark';
      apply(next);
      persist(next);
      btn.setAttribute('aria-label', label(next));
      btn.setAttribute('title', label(next));
    });

    // Text-size scaler, sits right next to the theme toggle. The stacked A's are
    // the conventional text-size affordance; clicking cycles through SCALES.
    var scaleBtn = document.createElement('button');
    scaleBtn.type = 'button';
    scaleBtn.className = 'font-scale-toggle';
    scaleBtn.innerHTML =
      '<span class="fs-a-sm" aria-hidden="true">A</span>' +
      '<span class="fs-a-lg" aria-hidden="true">A</span>';
    var scale = storedScale();
    scaleBtn.setAttribute('aria-label', scaleLabel(scale));
    scaleBtn.setAttribute('title', scaleLabel(scale));

    scaleBtn.addEventListener('click', function () {
      scale = SCALES[(SCALES.indexOf(scale) + 1) % SCALES.length];
      applyScale(scale);
      writePref('fontScale', scale);
      scaleBtn.setAttribute('aria-label', scaleLabel(scale));
      scaleBtn.setAttribute('title', scaleLabel(scale));
    });

    // Find a host generically: prefer the shared .topbar header, then any
    // <header>, then fall back to <body> so the control is never lost.
    var host = document.querySelector('.topbar') ||
               document.querySelector('header') ||
               document.body;
    host.appendChild(scaleBtn);
    host.appendChild(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }

  // Track OS preference changes only while the user hasn't made an explicit
  // choice (nothing persisted yet).
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: light)');
    var onChange = function (e) {
      if (stored()) return;
      apply(e.matches ? 'light' : 'dark');
    };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }
})();
