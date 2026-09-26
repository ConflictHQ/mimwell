/* ──────────────────────────────────────────────────────────────────────────
   KBRender — shared rich-markdown renderer for the client portal template.

   One module the whole portal uses so every markdown surface renders the same:
   tables, GFM task lists, footnotes, fenced-code syntax highlighting (highlight.js),
   GitHub-style callouts ([!NOTE]/[!TIP]/[!IMPORTANT]/[!WARNING]/[!CAUTION]),
   Mermaid diagrams (theme-aware, re-run safe), and responsive image / iframe
   embeds — all from a safe subset of HTML (untrusted raw HTML is escaped).

   Dependencies (load order does not matter; KBRender degrades if absent):
     - marked          (required)   — https://cdn.jsdelivr.net/npm/marked/marked.min.js
     - mermaid@11       (optional)   — diagrams; else ```mermaid stays a code block
     - highlight.js     (optional)   — lazy-loaded from CDN on first code block
   Styles live in app/render.css (link it on the page). The rendered container
   gets class `.md`.

   API (see bottom of file):
     KBRender.render(markdown, targetEl, opts?) -> targetEl   (full render)
     KBRender.parse(markdown, opts?)            -> html string (no enhancements)
     KBRender.enhance(scopeEl)                  -> applies highlight + mermaid to a subtree
     KBRender.renderMermaid(scopeEl)            -> (re)render mermaid in a subtree
     KBRender.highlight(scopeEl)                -> syntax-highlight code in a subtree
     KBRender.refreshTheme()                    -> re-theme mermaid for current data-theme
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  var HLJS_CSS = 'https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github-dark.min.css';
  var HLJS_JS  = 'https://cdn.jsdelivr.net/npm/highlight.js@11/lib/common.min.js';
  var PLOTLY_JS = 'https://cdn.jsdelivr.net/npm/plotly.js-dist-min@2/plotly.min.js';

  // The full-page diagram canvas (#42) ships beside this file. Resolve it off
  // our own <script src> so it loads wherever app/ is mounted rather than from
  // a baked absolute path; the literal is only a fallback for exotic loaders.
  var SELF_SRC = (document.currentScript && document.currentScript.src) || '';
  var KBCANVAS_JS = /render\.js(\?|#|$)/.test(SELF_SRC)
    ? SELF_SRC.replace(/render\.js(\?|#|$)/, 'kb-canvas.js$1')
    : '/app/kb-canvas.js';

  // ── HTML escaping ──────────────────────────────────────────────────────────
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ── Theme detection ──────────────────────────────────────────────────────────
  function currentTheme() {
    var t = document.documentElement.dataset.theme;
    return t === 'light' ? 'light' : 'dark';
  }

  // ── Mermaid ──────────────────────────────────────────────────────────────────
  var mermaidInit = false;
  var mermaidTheme = null;     // theme mermaid was last initialized with
  var mermaidSeq = 0;

  // Pull a few palette values off a probe element so diagrams match the page.
  function mermaidThemeVars() {
    var cs = getComputedStyle(document.documentElement);
    // Resolve any CSS color expression (color-mix, nested var()) to a concrete
    // rgb() via a probe element: mermaid's parser only accepts hex/rgb/hsl and
    // throws on modern color functions, which silently killed every diagram.
    function resolveColor(x) {
      if (!x || x.indexOf('(') === -1 || /^(rgb|hsl)a?\(/.test(x)) return x;
      // A style/getComputedStyle probe is not enough: Chrome resolves
      // color-mix() to a color(srgb ...) value mermaid rejects just the same.
      // A 1px canvas normalizes ANY supported color expression to raw pixels.
      try {
        var cv = document.createElement('canvas');
        cv.width = cv.height = 1;
        var ctx = cv.getContext('2d', { willReadFrequently: true });
        ctx.fillStyle = x;
        ctx.fillRect(0, 0, 1, 1);
        var d = ctx.getImageData(0, 0, 1, 1).data;
        return 'rgb(' + d[0] + ', ' + d[1] + ', ' + d[2] + ')';
      } catch (e) { return x; }
    }
    function v(name, fallback) {
      var x = cs.getPropertyValue(name).trim();
      return resolveColor(x || fallback);
    }
    return {
      primaryColor:       v('--surface2', '#222'),
      primaryTextColor:   v('--text', '#fff'),
      primaryBorderColor: v('--border2', '#444'),
      lineColor:          v('--muted', '#999'),
      secondaryColor:     v('--surface', '#1a1a1a'),
      tertiaryColor:      v('--surface', '#1a1a1a'),
      fontFamily:         (cs.getPropertyValue('--kb-font-body').trim() || 'sans-serif')
    };
  }

  function initMermaid(force) {
    if (!window.mermaid) return false;
    var theme = currentTheme();
    if (mermaidInit && mermaidTheme === theme && !force) return true;
    try {
      window.mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',           // no click-bound JS / raw HTML in labels
        theme: theme === 'light' ? 'default' : 'dark',
        themeVariables: mermaidThemeVars(),
        flowchart: { useMaxWidth: true, htmlLabels: false }
      });
      mermaidInit = true;
      mermaidTheme = theme;
      return true;
    } catch (e) { return false; }
  }

  // Render every ```mermaid block within `scope` into an SVG. Re-run safe: a
  // block already rendered (data-processed) is skipped, and a re-clone of an
  // un-rendered source (the pagination case) is picked up fresh each call.
  function renderMermaid(scope) {
    if (!scope || !initMermaid()) return;
    var sources = scope.querySelectorAll('code.language-mermaid, pre > code.language-mermaid');
    var divs = [];
    sources.forEach(function (code) {
      var pre = code.closest('pre') || code;
      var div = document.createElement('div');
      div.className = 'mermaid';
      div.id = 'kb-mmd-' + (mermaidSeq++);
      div.textContent = code.textContent;
      // Stash the mermaid source now, while textContent is still the original
      // source, so refreshTheme can re-render code-block-derived diagrams on a
      // theme flip (the outer wrapper's stamp only catches pre-existing divs).
      div.setAttribute('data-kb-src', code.textContent);
      pre.replaceWith(div);
      divs.push(div);
    });
    // Also pick up any .mermaid divs that haven't been processed yet.
    scope.querySelectorAll('div.mermaid:not([data-processed])').forEach(function (d) {
      if (divs.indexOf(d) === -1) divs.push(d);
    });
    if (!divs.length) return;
    try {
      var p = window.mermaid.run({ nodes: divs });
      if (p && p.then) {
        p.then(function () { attachCanvasAffordance(divs); })
         .catch(function () { markMermaidFailed(divs); });
      } else {
        attachCanvasAffordance(divs);
      }
    } catch (e) { markMermaidFailed(divs); }
  }

  // Load the canvas viewer on demand (the ensureHljs/ensurePlotly pattern): the
  // first diagram that actually renders pulls it in, so a page with no diagram
  // never fetches it. Resolves to null if the file is missing — the affordance
  // is then simply not attached and the inline diagram still stands on its own.
  var canvasLoading = null;
  function ensureCanvas() {
    if (window.KBCanvas) return Promise.resolve(window.KBCanvas);
    if (canvasLoading) return canvasLoading;
    canvasLoading = new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = KBCANVAS_JS;
      s.onload = function () { resolve(window.KBCanvas || null); };
      s.onerror = function () { resolve(null); };
      document.head.appendChild(s);
    });
    return canvasLoading;
  }

  // #42 — "Open in full view" affordance on rendered diagrams. The host div is
  // marked .kb-has-canvas (positioning context for the button) and the button
  // opens a clone of the rendered SVG in the full-page pan/zoom canvas.
  function attachCanvasAffordance(divs) {
    var pending = divs.filter(function (d) {
      return d && !d.hasAttribute('data-failed') && d.querySelector('svg') &&
        !d.classList.contains('kb-has-canvas');
    });
    if (!pending.length) return;
    ensureCanvas().then(function (canvas) {
      if (!canvas) return;
      pending.forEach(function (d) {
        if (d.classList.contains('kb-has-canvas')) return;
        d.classList.add('kb-has-canvas');
        canvas.attachAffordance(d, function () { return d.querySelector('svg'); }, { title: 'Diagram' });
      });
    });
  }

  function markMermaidFailed(divs) {
    divs.forEach(function (d) {
      if (!d.querySelector('svg')) d.setAttribute('data-failed', '');
    });
  }

  // ── highlight.js (lazy) ───────────────────────────────────────────────────────
  var hljsLoading = null;
  function ensureHljs() {
    if (window.hljs) return Promise.resolve(window.hljs);
    if (hljsLoading) return hljsLoading;
    hljsLoading = new Promise(function (resolve) {
      if (!document.querySelector('link[data-kb-hljs]')) {
        var link = document.createElement('link');
        link.rel = 'stylesheet'; link.href = HLJS_CSS; link.setAttribute('data-kb-hljs', '');
        document.head.appendChild(link);
      }
      var s = document.createElement('script');
      s.src = HLJS_JS;
      s.onload = function () { resolve(window.hljs || null); };
      s.onerror = function () { resolve(null); };
      document.head.appendChild(s);
    });
    return hljsLoading;
  }

  function highlight(scope) {
    if (!scope) return;
    var blocks = scope.querySelectorAll('pre > code[class*="language-"]:not(.language-mermaid):not([data-hl])');
    if (!blocks.length) return;
    ensureHljs().then(function (hljs) {
      if (!hljs) return;
      blocks.forEach(function (code) {
        if (code.getAttribute('data-hl')) return;
        try { hljs.highlightElement(code); } catch (e) { /* leave plain */ }
        code.setAttribute('data-hl', '1');
      });
    });
  }

  // ── Plotly (#43, lazy) ────────────────────────────────────────────────────────
  // A ```plotly fenced block whose body is a JSON figure spec ({ data, layout,
  // config? }) becomes an interactive, theme-aware chart. ONLY JSON is accepted
  // — the body is JSON.parse'd, never eval'd — so no arbitrary JS can run. The
  // Plotly bundle lazy-loads from the CDN on first chart (ensureHljs pattern),
  // so pages with no chart pay nothing.
  var plotlyLoading = null;
  function ensurePlotly() {
    if (window.Plotly) return Promise.resolve(window.Plotly);
    if (plotlyLoading) return plotlyLoading;
    plotlyLoading = new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = PLOTLY_JS;
      s.onload = function () { resolve(window.Plotly || null); };
      s.onerror = function () { resolve(null); };
      document.head.appendChild(s);
    });
    return plotlyLoading;
  }

  // Map the --kb-* / local-alias palette into a Plotly layout so charts theme
  // light/dark off the same seam (#40) with no hardcoded colors. Returns a
  // partial layout merged UNDER the spec's own layout (spec wins).
  function plotlyThemeLayout() {
    var cs = getComputedStyle(document.documentElement);
    function v(name, fallback) { var x = cs.getPropertyValue(name).trim(); return x || fallback; }
    var text = v('--text', '#fff');
    var grid = v('--border', 'rgba(255,255,255,0.2)');
    var muted = v('--muted', '#999');
    var font = v('--kb-font-body', 'sans-serif');
    var accents = [v('--red', '#1E9C8F'), v('--blue', '#2F97BF'), v('--green', '#B98536'),
                   v('--yellow', '#F5A623'), v('--purple', '#7A5BA8')];
    var axis = { gridcolor: grid, zerolinecolor: grid, linecolor: grid,
                 tickfont: { color: muted }, titlefont: { color: muted } };
    return {
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      font: { color: text, family: font },
      colorway: accents,
      xaxis: axis, yaxis: axis,
      legend: { font: { color: text } },
      margin: { t: 36, r: 18, b: 40, l: 48 }
    };
  }

  function shallowMergeLayout(base, over) {
    var out = {};
    var k;
    for (k in base) if (Object.prototype.hasOwnProperty.call(base, k)) out[k] = base[k];
    for (k in (over || {})) if (Object.prototype.hasOwnProperty.call(over, k)) {
      // Merge one level into axis/legend/font objects so theme defaults survive.
      if (out[k] && typeof out[k] === 'object' && over[k] && typeof over[k] === 'object'
          && !Array.isArray(over[k])) {
        out[k] = shallowMergeLayout(out[k], over[k]);
      } else {
        out[k] = over[k];
      }
    }
    return out;
  }

  function drawPlotly(div, spec) {
    ensurePlotly().then(function (Plotly) {
      if (!Plotly) { div.setAttribute('data-failed', ''); div.textContent = 'Plotly failed to load.'; return; }
      var layout = shallowMergeLayout(plotlyThemeLayout(), spec.layout || {});
      var config = spec.config || {};
      config.responsive = config.responsive !== false;   // responsive by default
      if (config.displaylogo === undefined) config.displaylogo = false;
      try {
        Plotly.react(div, spec.data || [], layout, config);
      } catch (e) { div.setAttribute('data-failed', ''); div.textContent = 'Chart could not be rendered.'; }
    });
  }

  function transformPlotly(scope) {
    var blocks = scope.querySelectorAll('pre > code.language-plotly:not([data-kb-plotly])');
    blocks.forEach(function (code) {
      code.setAttribute('data-kb-plotly', '1');
      var spec;
      try { spec = JSON.parse(code.textContent); }
      catch (e) { return; }  // not valid JSON → leave the code block as-is
      if (!spec || typeof spec !== 'object' || !Array.isArray(spec.data)) return;
      var div = document.createElement('div');
      div.className = 'kb-plotly';
      div.setAttribute('data-kb-plotly-src', code.textContent);
      var pre = code.closest('pre') || code;
      pre.replaceWith(div);
      drawPlotly(div, spec);
    });
  }

  // ── marked configuration ──────────────────────────────────────────────────────
  var configured = false;
  function configure() {
    if (configured || !window.marked) return;
    window.marked.setOptions({
      gfm: true,
      breaks: false,
      headerIds: true,
      mangle: false
    });
    configured = true;
  }

  // ── Callout / admonition transform ───────────────────────────────────────────
  // Rewrites GitHub-style admonition blockquotes in the rendered DOM:
  //   > [!NOTE]
  //   > body…
  // into a styled .callout box. Operates on <blockquote> elements after parse so
  // it composes with marked's blockquote handling and stays sanitization-safe.
  var CALLOUTS = {
    NOTE:      { cls: 'callout-note',      ico: 'ⓘ', label: 'Note' },
    TIP:       { cls: 'callout-tip',       ico: '✓', label: 'Tip' },
    IMPORTANT: { cls: 'callout-important', ico: '★', label: 'Important' },
    WARNING:   { cls: 'callout-warning',   ico: '⚠', label: 'Warning' },
    CAUTION:   { cls: 'callout-caution',   ico: '⚠', label: 'Caution' }
  };
  var CALLOUT_RE = /^\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*)$/i;

  function transformCallouts(scope) {
    scope.querySelectorAll('blockquote').forEach(function (bq) {
      var first = bq.querySelector('p');
      if (!first) return;
      // The marker lives at the very start of the first paragraph's text.
      var firstText = first.textContent || '';
      var m = CALLOUT_RE.exec(firstText.split('\n')[0]);
      if (!m) return;
      var kind = CALLOUTS[m[1].toUpperCase()];
      if (!kind) return;

      // Strip the marker line from the first paragraph. If a title followed the
      // marker on the same line, keep it as the heading instead of the default.
      var customTitle = (m[2] || '').trim();
      var rest = firstText.replace(CALLOUT_RE, '').replace(/^\n/, '');
      if (rest.trim()) first.textContent = rest; else first.remove();

      var box = document.createElement('div');
      box.className = 'callout ' + kind.cls;
      var title = document.createElement('div');
      title.className = 'callout-title';
      title.innerHTML = '<span class="callout-ico">' + esc(kind.ico) + '</span>' +
        '<span>' + esc(customTitle || kind.label) + '</span>';
      var body = document.createElement('div');
      body.className = 'callout-body';
      while (bq.firstChild) body.appendChild(bq.firstChild);
      box.appendChild(title);
      box.appendChild(body);
      bq.replaceWith(box);
    });
  }

  // ── Embed transform ───────────────────────────────────────────────────────────
  // Safe convention for external diagrams: an autolink/explicit link whose href
  // ends in a known iframe-able pattern, written on its own line, becomes a
  // responsive iframe. Everything else stays a normal link. Only https URLs from
  // an allowlist of hosts are framed; others are left as links (no injection).
  var EMBED_HOSTS = [
    'www.youtube.com', 'youtube.com', 'youtube-nocookie.com',
    'player.vimeo.com', 'docs.google.com', 'drive.google.com',
    'miro.com', 'app.diagrams.net', 'viewer.diagrams.net', 'whimsical.com',
    'lucid.app', 'figma.com', 'www.figma.com',
    // OneDrive / SharePoint (#41): consumer hosts are exact, SharePoint tenants
    // are *.sharepoint.com (matched by suffix below).
    'onedrive.live.com', '1drv.ms', 'www.onedrive.live.com'
  ];
  // Host suffixes accepted in addition to the exact list (tenant subdomains).
  var EMBED_HOST_SUFFIXES = ['.sharepoint.com'];
  function isEmbeddable(url) {
    try {
      var u = new URL(url);
      if (u.protocol !== 'https:') return false;
      if (EMBED_HOSTS.indexOf(u.hostname) !== -1) return true;
      return EMBED_HOST_SUFFIXES.some(function (sfx) {
        return u.hostname.length > sfx.length && u.hostname.slice(-sfx.length) === sfx;
      });
    } catch (e) { return false; }
  }
  // ── Cloud-drive link previews (#66) ─────────────────────────────────────────
  // A PLAIN link (no "embed:" opt-in) to a recognized cloud-drive share URL
  // gets a small preview CHIP appended after it — a file-type label and an
  // outbound affordance, so a reader can tell what's on the other end of a
  // drive link without following it. This is recognition, not a live fetch:
  // the portal has no OAuth to any drive host, so there is no title/thumbnail
  // to pull — the chip is built entirely from the URL SHAPE. Graceful
  // fallback is the point: an unrecognized shape (or a link already turned
  // into a full embed by transformEmbeds) is left exactly as authored.
  var DRIVE_KIND_RULES = [
    { host: /(^|\.)docs\.google\.com$/, path: /^\/document\//, label: 'Google Doc' },
    { host: /(^|\.)docs\.google\.com$/, path: /^\/spreadsheets\//, label: 'Google Sheet' },
    { host: /(^|\.)docs\.google\.com$/, path: /^\/presentation\//, label: 'Google Slides' },
    { host: /(^|\.)docs\.google\.com$/, path: /^\/forms\//, label: 'Google Form' },
    { host: /(^|\.)drive\.google\.com$/, path: /^\/drive\/folders\//, label: 'Drive Folder' },
    { host: /(^|\.)drive\.google\.com$/, path: /.*/, label: 'Drive File' },
    { host: /(^|\.)sharepoint\.com$/, path: /.*/, label: 'SharePoint' },
    { host: /^(www\.)?onedrive\.live\.com$/, path: /.*/, label: 'OneDrive' },
    { host: /^1drv\.ms$/, path: /.*/, label: 'OneDrive' },
    { host: /^(www\.)?dropbox\.com$/, path: /^\/(s|scl\/fi|sh)\//, label: 'Dropbox' },
    { host: /^app\.box\.com$/, path: /^\/s\//, label: 'Box' },
  ];
  function driveKind(url) {
    var u;
    try { u = new URL(url); } catch (e) { return null; }
    if (u.protocol !== 'https:') return null;
    for (var i = 0; i < DRIVE_KIND_RULES.length; i++) {
      var rule = DRIVE_KIND_RULES[i];
      if (rule.host.test(u.hostname) && rule.path.test(u.pathname)) return rule.label;
    }
    return null;
  }
  function transformDrivePreviews(scope) {
    scope.querySelectorAll('a[href]').forEach(function (a) {
      if (a.closest('.kb-embed')) return; // already a full embed (transformEmbeds)
      if (a.querySelector('.kb-drive-chip')) return; // idempotent on re-enhance
      var href = a.getAttribute('href') || '';
      var kind = driveKind(href);
      if (!kind) return;
      var chip = document.createElement('span');
      chip.className = 'kb-drive-chip';
      chip.setAttribute('aria-hidden', 'true');
      chip.innerHTML = '<span class="kb-drive-ico">▤</span><span class="kb-drive-label">' + esc(kind) + '</span>';
      a.appendChild(document.createTextNode(' '));
      a.appendChild(chip);
    });
  }

  function transformEmbeds(scope) {
    // A paragraph that is exactly one anchor whose href is an embeddable URL
    // and whose link text is "embed:" (explicit opt-in) becomes an iframe.
    scope.querySelectorAll('p > a').forEach(function (a) {
      var p = a.parentNode;
      if (p.childNodes.length !== 1) return;
      var href = a.getAttribute('href') || '';
      var label = (a.textContent || '').trim().toLowerCase();
      if (label !== 'embed' && label !== 'embed:') return;
      if (!isEmbeddable(href)) return;
      var wrap = document.createElement('div');
      wrap.className = 'kb-embed';
      var iframe = document.createElement('iframe');
      iframe.src = href;
      iframe.loading = 'lazy';
      iframe.setAttribute('allowfullscreen', '');
      iframe.setAttribute('referrerpolicy', 'no-referrer');
      iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-popups allow-forms allow-presentation');
      wrap.appendChild(iframe);
      p.replaceWith(wrap);
    });
  }

  // ── Sanitize: strip dangerous nodes/attrs from the rendered subset ────────────
  // marked does not execute scripts, but untrusted markdown can contain raw HTML.
  // We allow a safe subset by removing <script>/<style>/<iframe>/<object> (except
  // our own .kb-embed iframes built above), event handler attributes, and
  // javascript: URLs. Run BEFORE the embed/callout transforms add trusted nodes.
  var BANNED_TAGS = ['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'LINK', 'META', 'BASE', 'FORM'];
  function sanitize(scope) {
    BANNED_TAGS.forEach(function (tag) {
      scope.querySelectorAll(tag.toLowerCase()).forEach(function (n) { n.remove(); });
    });
    var all = scope.querySelectorAll('*');
    all.forEach(function (el) {
      for (var i = el.attributes.length - 1; i >= 0; i--) {
        var attr = el.attributes[i];
        var name = attr.name.toLowerCase();
        var val = attr.value || '';
        if (name.indexOf('on') === 0) { el.removeAttribute(attr.name); continue; }
        if ((name === 'href' || name === 'src' || name === 'xlink:href') &&
            /^\s*javascript:/i.test(val)) {
          el.removeAttribute(attr.name);
        }
      }
    });
  }

  // ── Public render pipeline ────────────────────────────────────────────────────
  function parse(markdown, opts) {
    configure();
    if (!window.marked) return esc(markdown);
    return window.marked.parse(String(markdown == null ? '' : markdown), opts || {});
  }

  // Annotate fenced blocks with a language tag for the CSS label, and ensure the
  // standard language-* class shape highlight.js expects.
  function tagCodeBlocks(scope) {
    scope.querySelectorAll('pre > code[class*="language-"]').forEach(function (code) {
      var m = /language-([\w+-]+)/.exec(code.className);
      if (m && m[1] && m[1] !== 'mermaid') {
        code.closest('pre').setAttribute('data-lang', m[1]);
      }
    });
  }

  // Apply every enhancement to an already-parsed subtree (used by render and by
  // paginated re-renders that clone parsed HTML into the page).
  function enhance(scope) {
    if (!scope) return scope;
    sanitize(scope);
    transformCallouts(scope);
    transformEmbeds(scope);
    transformDrivePreviews(scope);
    transformPlotly(scope);
    tagCodeBlocks(scope);
    renderMermaid(scope);
    highlight(scope);
    return scope;
  }

  // Full render: parse markdown → inject into target (with .md class) → enhance.
  function render(markdown, targetEl, opts) {
    if (!targetEl) return targetEl;
    targetEl.classList.add('md');
    targetEl.innerHTML = parse(markdown, opts);
    enhance(targetEl);
    return targetEl;
  }

  // Re-theme mermaid for the current data-theme and re-render existing diagrams.
  // Mermaid bakes colors into the SVG at render time, so a theme flip needs a
  // re-run from the original source. We keep source on a data attribute.
  function refreshTheme(scope) {
    scope = scope || document;
    initMermaid(true);
    scope.querySelectorAll('div.mermaid[data-processed]').forEach(function (d) {
      var src = d.getAttribute('data-kb-src');
      if (src == null) return;
      d.removeAttribute('data-processed');
      d.removeAttribute('data-failed');
      d.innerHTML = '';
      d.textContent = src;
    });
    renderMermaid(scope);
    // Re-theme Plotly charts (#43): re-draw from the stashed JSON spec so the
    // palette flips with the page. No-op when Plotly never loaded.
    if (window.Plotly) {
      scope.querySelectorAll('div.kb-plotly[data-kb-plotly-src]').forEach(function (d) {
        try {
          var spec = JSON.parse(d.getAttribute('data-kb-plotly-src'));
          if (spec && Array.isArray(spec.data)) drawPlotly(d, spec);
        } catch (e) { /* leave as-is */ }
      });
    }
  }

  // Stash mermaid source before run so refreshTheme can re-render after a flip.
  var _origRenderMermaid = renderMermaid;
  renderMermaid = function (scope) {
    if (scope) {
      scope.querySelectorAll('div.mermaid:not([data-kb-src])').forEach(function (d) {
        d.setAttribute('data-kb-src', d.textContent);
      });
    }
    return _origRenderMermaid(scope);
  };

  // Re-theme diagrams automatically when the theme toggles.
  if (window.MutationObserver) {
    new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        if (muts[i].attributeName === 'data-theme') { refreshTheme(document); break; }
      }
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  }

  window.KBRender = {
    render: render,
    parse: parse,
    enhance: enhance,
    renderMermaid: renderMermaid,
    highlight: highlight,
    refreshTheme: refreshTheme,
    esc: esc
  };
})();
