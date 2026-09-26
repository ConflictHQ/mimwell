/* ──────────────────────────────────────────────────────────────────────────
   KBDocViewer — in-portal document viewer for the client portal template.

   Dispatches by file type and renders the document client-side, lazy-loading
   each viewer library from a CDN (the ensureHljs() pattern in render.js) so a
   page that opens no document of a given type pays nothing:

     • PDF  → PDF.js (paged canvases, scrollable, zoom; native <embed> fallback)
     • DOCX → mammoth.js → HTML, rendered through KBRender (.md) so callouts /
              links / tables get the house treatment
     • CSV  → Papa Parse → a sortable table
     • XLSX → SheetJS (xlsx) → a table with sheet tabs

   Reachability-based with graceful fallback: an unsupported extension, a load
   failure, or a missing/unreachable file degrades to an icon + download /
   open-in-new-tab link. Remote Office docs (Drive/OneDrive/SharePoint) embed via
   the Office Online viewer iframe where the host allows it.

   No CSP header exists in _headers, so these CDN loads need no header change.

   Styling lives in app/doc-viewer.css; the DOCX path reuses app/render.css.
   Each library maps the --kb-* / local-alias palette into its OWN chrome (the
   #40 seam), so a data-theme flip reskins the viewers with no per-lib JS here.

   API:
     KBDocViewer.canView(pathOrUrl)        -> boolean (a supported extension)
     KBDocViewer.render(pathOrUrl, el, opts?) -> Promise (renders into el)
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  // Pinned CDN bundles (lazy-loaded on first use of each type).
  var CDN = {
    pdfjs:  'https://cdn.jsdelivr.net/npm/pdfjs-dist@4/build/pdf.min.mjs',
    pdfworker: 'https://cdn.jsdelivr.net/npm/pdfjs-dist@4/build/pdf.worker.min.mjs',
    mammoth: 'https://cdn.jsdelivr.net/npm/mammoth@1/mammoth.browser.min.js',
    papa:    'https://cdn.jsdelivr.net/npm/papaparse@5/papaparse.min.js',
    xlsx:    'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js'
  };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function extOf(path) {
    var clean = String(path || '').split('?')[0].split('#')[0];
    var m = /\.([a-z0-9]+)$/i.exec(clean);
    return m ? m[1].toLowerCase() : '';
  }
  var SUPPORTED = { pdf: 1, docx: 1, csv: 1, xlsx: 1, xls: 1 };
  function canView(path) { return !!SUPPORTED[extOf(path)]; }

  function isRemote(path) { return /^https?:\/\//i.test(String(path || '')); }

  // ── Lazy CDN loaders (resolve the global, or null on failure) ──────────────
  var loading = {};
  function loadScript(key, src, globalName, isModule) {
    if (globalName && window[globalName]) return Promise.resolve(window[globalName]);
    if (loading[key]) return loading[key];
    loading[key] = new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = src;
      if (isModule) s.type = 'module';
      s.onload = function () { resolve(globalName ? (window[globalName] || true) : true); };
      s.onerror = function () { resolve(null); };
      document.head.appendChild(s);
    });
    return loading[key];
  }

  function fallback(el, path, message) {
    var name = String(path).split('/').pop();
    el.innerHTML =
      '<div class="kb-doc-fallback">' +
        '<div class="kb-doc-ico" aria-hidden="true">▤</div>' +
        '<div class="kb-doc-fallmsg">' + esc(message || 'Preview unavailable for this document.') + '</div>' +
        '<a class="kb-doc-dl" href="' + esc(path) + '" target="_blank" rel="noopener" download>' +
          'Download ' + esc(name) + ' ↗</a>' +
      '</div>';
  }

  function spinner(el, label) {
    el.innerHTML = '<div class="kb-doc-loading"><span class="kb-doc-spin"></span>' +
      '<span>' + esc(label || 'Loading document…') + '</span></div>';
  }

  // ── PDF ────────────────────────────────────────────────────────────────────
  function renderPdf(path, el) {
    spinner(el, 'Loading PDF…');
    // pdf.js v4 ships as an ES module; import() it directly (no global needed).
    return import(CDN.pdfjs).then(function (pdfjsLib) {
      pdfjsLib.GlobalWorkerOptions.workerSrc = CDN.pdfworker;
      return pdfjsLib.getDocument(path).promise;
    }).then(function (pdf) {
      el.innerHTML = '<div class="kb-doc-pdf"></div>';
      var host = el.querySelector('.kb-doc-pdf');
      var chain = Promise.resolve();
      for (var n = 1; n <= pdf.numPages; n++) {
        (function (pageNum) {
          chain = chain.then(function () {
            return pdf.getPage(pageNum).then(function (page) {
              var vp = page.getViewport({ scale: 1.4 });
              var canvas = document.createElement('canvas');
              canvas.className = 'kb-doc-page';
              canvas.width = vp.width; canvas.height = vp.height;
              host.appendChild(canvas);
              return page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;
            });
          });
        })(n);
      }
      return chain;
    }).catch(function () {
      // Native embed fallback (browsers with a built-in PDF plugin), else link.
      el.innerHTML = '<embed class="kb-doc-embed" src="' + esc(path) + '" type="application/pdf">';
      var em = el.querySelector('.kb-doc-embed');
      em.addEventListener('error', function () { fallback(el, path, 'This PDF could not be displayed.'); });
    });
  }

  // ── DOCX (mammoth → HTML → KBRender) ───────────────────────────────────────
  function renderDocx(path, el) {
    spinner(el, 'Loading document…');
    return loadScript('mammoth', CDN.mammoth, 'mammoth').then(function (mammoth) {
      if (!mammoth) { fallback(el, path, 'The DOCX viewer failed to load.'); return; }
      return fetch(path).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.arrayBuffer();
      }).then(function (buf) {
        return mammoth.convertToHtml({ arrayBuffer: buf });
      }).then(function (res) {
        var box = document.createElement('div');
        box.className = 'kb-doc-docx md';
        box.innerHTML = res.value || '';
        // Run the shared enhancement pass (sanitize + callouts + tables + code).
        if (window.KBRender && KBRender.enhance) KBRender.enhance(box);
        el.innerHTML = '';
        el.appendChild(box);
      });
    }).catch(function () { fallback(el, path, 'This document could not be displayed.'); });
  }

  // ── CSV (Papa Parse → sortable table) ──────────────────────────────────────
  function renderCsv(path, el) {
    spinner(el, 'Loading table…');
    return loadScript('papa', CDN.papa, 'Papa').then(function (Papa) {
      if (!Papa) { fallback(el, path, 'The CSV viewer failed to load.'); return; }
      return fetch(path).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.text();
      }).then(function (text) {
        var parsed = Papa.parse(text.trim(), { skipEmptyLines: true });
        var rows = parsed.data || [];
        if (!rows.length) { el.innerHTML = '<div class="kb-doc-empty">Empty table.</div>'; return; }
        el.innerHTML = '';
        el.appendChild(buildTable(rows[0], rows.slice(1)));
      });
    }).catch(function () { fallback(el, path, 'This table could not be displayed.'); });
  }

  // ── XLSX (SheetJS → sheet tabs + tables) ───────────────────────────────────
  function renderXlsx(path, el) {
    spinner(el, 'Loading spreadsheet…');
    return loadScript('xlsx', CDN.xlsx, 'XLSX').then(function (XLSX) {
      if (!XLSX) { fallback(el, path, 'The spreadsheet viewer failed to load.'); return; }
      return fetch(path).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.arrayBuffer();
      }).then(function (buf) {
        var wb = XLSX.read(buf, { type: 'array' });
        var names = wb.SheetNames || [];
        if (!names.length) { el.innerHTML = '<div class="kb-doc-empty">No sheets.</div>'; return; }
        el.innerHTML =
          '<div class="kb-doc-tabs" role="tablist"></div>' +
          '<div class="kb-doc-sheet"></div>';
        var tabBar = el.querySelector('.kb-doc-tabs');
        var sheetHost = el.querySelector('.kb-doc-sheet');

        function showSheet(idx) {
          var rows = XLSX.utils.sheet_to_json(wb.Sheets[names[idx]], { header: 1, blankrows: false });
          sheetHost.innerHTML = '';
          if (!rows.length) { sheetHost.innerHTML = '<div class="kb-doc-empty">Empty sheet.</div>'; }
          else sheetHost.appendChild(buildTable(rows[0], rows.slice(1)));
          tabBar.querySelectorAll('.kb-doc-tab').forEach(function (b, i) {
            b.classList.toggle('active', i === idx);
            b.setAttribute('aria-selected', i === idx ? 'true' : 'false');
          });
        }

        tabBar.innerHTML = names.map(function (nm, i) {
          return '<button class="kb-doc-tab" type="button" role="tab" data-sheet="' + i + '">' +
            esc(nm) + '</button>';
        }).join('');
        tabBar.addEventListener('click', function (e) {
          var b = e.target.closest('.kb-doc-tab'); if (!b) return;
          showSheet(parseInt(b.getAttribute('data-sheet'), 10));
        });
        showSheet(0);
      });
    }).catch(function () { fallback(el, path, 'This spreadsheet could not be displayed.'); });
  }

  // ── Shared sortable table builder (CSV + XLSX) ─────────────────────────────
  function buildTable(headerRow, bodyRows) {
    var wrap = document.createElement('div');
    wrap.className = 'kb-doc-table-wrap';
    var table = document.createElement('table');
    table.className = 'kb-doc-table';

    var headers = (headerRow || []).map(function (h) { return h == null ? '' : String(h); });
    var thead = document.createElement('thead');
    var tr = document.createElement('tr');
    headers.forEach(function (h, i) {
      var th = document.createElement('th');
      th.textContent = h;
      th.setAttribute('data-col', i);
      th.setAttribute('role', 'button');
      th.tabIndex = 0;
      tr.appendChild(th);
    });
    thead.appendChild(tr);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    var data = (bodyRows || []).map(function (r) { return Array.isArray(r) ? r : [r]; });
    function paint(rows) {
      tbody.innerHTML = '';
      rows.forEach(function (row) {
        var rtr = document.createElement('tr');
        for (var i = 0; i < headers.length; i++) {
          var td = document.createElement('td');
          var v = row[i];
          td.textContent = v == null ? '' : String(v);
          rtr.appendChild(td);
        }
        tbody.appendChild(rtr);
      });
    }
    paint(data);
    table.appendChild(tbody);

    // Column sort: click a header to toggle asc/desc; numeric-aware.
    var sortState = { col: -1, dir: 1 };
    function sortBy(col) {
      sortState.dir = sortState.col === col ? -sortState.dir : 1;
      sortState.col = col;
      var sorted = data.slice().sort(function (a, b) {
        var x = a[col], y = b[col];
        var nx = parseFloat(x), ny = parseFloat(y);
        var both = !isNaN(nx) && !isNaN(ny);
        var cmp = both ? (nx - ny) : String(x == null ? '' : x).localeCompare(String(y == null ? '' : y));
        return cmp * sortState.dir;
      });
      paint(sorted);
      thead.querySelectorAll('th').forEach(function (th, i) {
        th.classList.toggle('sort-asc', i === col && sortState.dir === 1);
        th.classList.toggle('sort-desc', i === col && sortState.dir === -1);
      });
    }
    thead.addEventListener('click', function (e) {
      var th = e.target.closest('th'); if (!th) return;
      sortBy(parseInt(th.getAttribute('data-col'), 10));
    });
    thead.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var th = e.target.closest('th'); if (!th) return;
      e.preventDefault();
      sortBy(parseInt(th.getAttribute('data-col'), 10));
    });

    wrap.appendChild(table);
    return wrap;
  }

  // ── Office Online iframe (remote Drive/OneDrive/SharePoint office docs) ─────
  function renderRemoteOffice(path, el) {
    var src = 'https://view.officeapps.live.com/op/embed.aspx?src=' + encodeURIComponent(path);
    el.innerHTML = '<iframe class="kb-doc-office" src="' + esc(src) + '" ' +
      'referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>';
  }

  // ── Dispatch ────────────────────────────────────────────────────────────────
  function render(path, el, opts) {
    opts = opts || {};
    if (!el) return Promise.resolve();
    el.classList.add('kb-doc');
    var ext = extOf(path);
    if (ext === 'pdf') return renderPdf(path, el);
    if (ext === 'docx') {
      // A remote office doc can't always be fetched cross-origin — prefer the
      // Office viewer iframe for remote .docx/.xlsx; mammoth handles local ones.
      if (isRemote(path)) return Promise.resolve(renderRemoteOffice(path, el));
      return renderDocx(path, el);
    }
    if (ext === 'csv') return renderCsv(path, el);
    if (ext === 'xlsx' || ext === 'xls') {
      if (isRemote(path)) return Promise.resolve(renderRemoteOffice(path, el));
      return renderXlsx(path, el);
    }
    fallback(el, path, 'Preview is not supported for this file type.');
    return Promise.resolve();
  }

  window.KBDocViewer = { canView: canView, render: render, extOf: extOf };
})();
