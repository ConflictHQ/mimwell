/* ──────────────────────────────────────────────────────────────────────────
   KBCanvas — reusable full-page scrollable + zoomable canvas viewer.

   Opens any inline diagram or graph (Mermaid/Gantt SVG, dependency graph, the
   brain/KG node-edge renderers) in a full-page overlay with:
     • pan   — drag (mouse) / one-finger drag (touch)
     • zoom  — wheel, pinch, + / − buttons, double-click
     • fit-to-screen, reset (1:1), fullscreen
     • keyboard — arrows pan, +/−/0 zoom, f fit, Esc close

   Self-contained: pan/zoom is a pure CSS transform on a stage element; no
   external CDN. Works on anything you hand it — an <svg>, or any DOM node.

   Adopters call:
     KBCanvas.open(svgOrNode, { title })   // clones the node into the overlay
   render.js adds an "open in full view" affordance to inline .mermaid blocks
   that calls this; the brain/KG/deps/Gantt surfaces adopt the same entry point.

   Loading: render.js injects this file on demand the first time a page actually
   renders a diagram, so a page with no diagram pays nothing. That is also why
   the chrome ships as an injected <style> here instead of a sibling stylesheet:
   a stylesheet would have to be <link>ed by every page up front, whether or not
   the viewer is ever loaded, which is exactly the cost the lazy load avoids.
   All chrome themes off the --kb-* seam (with literal fallbacks for pages that
   do not define it); no palette is hardcoded.

   API:
     KBCanvas.open(node, opts?)   -> opens the overlay with a clone of `node`
     KBCanvas.close()
     KBCanvas.attachAffordance(container, getNode, opts?)
        -> injects a themed "⤢ Full view" button into `container`; on click it
           opens KBCanvas with the node returned by getNode().
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  var MIN = 0.1, MAX = 8;
  var ov = null, stage, viewport, scaleEl;
  var scale = 1, tx = 0, ty = 0;
  var drag = null;          // { x, y, tx, ty }
  var pinch = null;         // { dist, scale, cx, cy }

  function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

  // ── Chrome (injected once, on first use) ──────────────────────────────────
  // Kept in the module so the whole viewer is a single lazy request. Every
  // color/font reads the --kb-* seam first and falls back to a literal only so
  // an unbranded page still renders legibly.
  var STYLE = [
    '.kb-canvas{display:none;position:fixed;inset:0;z-index:1200;flex-direction:column;',
      'background:var(--kb-bg-deep,#060D0F);}',
    '.kb-canvas.open{display:flex;}',
    '.kb-canvas-bar{flex:none;display:flex;align-items:center;justify-content:space-between;',
      'gap:12px;padding:8px 14px;background:var(--kb-bg,#0B1619);',
      'border-bottom:1px solid var(--kb-border,rgba(255,255,255,.2));}',
    '.kb-canvas-title{font-family:var(--kb-font-mono,monospace);font-size:11px;',
      'letter-spacing:.08em;text-transform:uppercase;color:var(--kb-text-muted,#93A9AB);',
      'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}',
    '.kb-canvas-tools{display:flex;align-items:center;gap:6px;flex:none;}',
    '.kb-canvas-tools button{font-family:var(--kb-font-mono,monospace);font-size:12px;',
      'line-height:1;cursor:pointer;padding:6px 10px;border-radius:3px;',
      'color:var(--kb-text,#fff);background:rgba(255,255,255,.06);',
      'border:1px solid var(--kb-border,rgba(255,255,255,.2));}',
    '.kb-canvas-tools button:hover{color:var(--kb-primary,#1E9C8F);',
      'border-color:var(--kb-primary,#1E9C8F);}',
    '.kb-canvas-tools button:focus-visible{outline:2px solid var(--kb-primary,#1E9C8F);',
      'outline-offset:2px;}',
    '.kb-canvas-scale{min-width:46px;text-align:center;font-family:var(--kb-font-mono,monospace);',
      'font-size:11px;color:var(--kb-text-muted,#93A9AB);}',
    // touch-action:none so one-finger pan / two-finger pinch reach the handlers
    // instead of scrolling the page behind the overlay.
    '.kb-canvas-viewport{flex:1;overflow:hidden;cursor:grab;touch-action:none;}',
    '.kb-canvas-viewport.grabbing{cursor:grabbing;}',
    '.kb-canvas-stage{transform-origin:0 0;width:max-content;}',
    '.kb-canvas-stage svg{max-width:none;height:auto;}',
    // The affordance render.js attaches to a rendered diagram block.
    '.kb-has-canvas{position:relative;}',
    '.kb-canvas-open{position:absolute;right:8px;top:8px;z-index:2;cursor:pointer;',
      'font-family:var(--kb-font-mono,monospace);font-size:10px;letter-spacing:.06em;',
      'text-transform:uppercase;padding:4px 9px;border-radius:3px;opacity:0;',
      'color:var(--kb-text-muted,#93A9AB);background:var(--kb-bg,#0B1619);',
      'border:1px solid var(--kb-border,rgba(255,255,255,.2));transition:opacity .15s,color .15s;}',
    '.kb-has-canvas:hover .kb-canvas-open,.kb-canvas-open:focus-visible{opacity:1;}',
    '.kb-canvas-open:hover{color:var(--kb-primary,#1E9C8F);}',
    '@media (max-width:560px){.kb-canvas-open{opacity:1;}}'
  ].join('');

  function ensureStyles() {
    if (document.getElementById('kb-canvas-style')) return;
    var s = document.createElement('style');
    s.id = 'kb-canvas-style';
    s.textContent = STYLE;
    document.head.appendChild(s);
  }

  function build() {
    if (ov) return;
    ensureStyles();
    ov = document.createElement('div');
    ov.className = 'kb-canvas';
    ov.setAttribute('role', 'dialog');
    ov.setAttribute('aria-modal', 'true');
    ov.innerHTML =
      '<div class="kb-canvas-bar">' +
        '<span class="kb-canvas-title"></span>' +
        '<div class="kb-canvas-tools">' +
          '<button type="button" data-act="out"  aria-label="Zoom out">−</button>' +
          '<span class="kb-canvas-scale">100%</span>' +
          '<button type="button" data-act="in"   aria-label="Zoom in">+</button>' +
          '<button type="button" data-act="fit"  aria-label="Fit to screen">Fit</button>' +
          '<button type="button" data-act="reset" aria-label="Reset to 100%">1:1</button>' +
          '<button type="button" data-act="full" aria-label="Toggle fullscreen">⛶</button>' +
          '<button type="button" data-act="close" aria-label="Close">✕</button>' +
        '</div>' +
      '</div>' +
      '<div class="kb-canvas-viewport"><div class="kb-canvas-stage"></div></div>';
    document.body.appendChild(ov);
    viewport = ov.querySelector('.kb-canvas-viewport');
    stage = ov.querySelector('.kb-canvas-stage');
    scaleEl = ov.querySelector('.kb-canvas-scale');

    ov.querySelector('.kb-canvas-tools').addEventListener('click', function (e) {
      var b = e.target.closest('button'); if (!b) return;
      var act = b.getAttribute('data-act');
      if (act === 'in') zoomBy(1.25);
      else if (act === 'out') zoomBy(0.8);
      else if (act === 'fit') fit();
      else if (act === 'reset') reset();
      else if (act === 'full') toggleFull();
      else if (act === 'close') close();
    });

    // Pan (mouse drag).
    viewport.addEventListener('mousedown', function (e) {
      if (e.button !== 0) return;
      drag = { x: e.clientX, y: e.clientY, tx: tx, ty: ty };
      viewport.classList.add('grabbing');
    });
    window.addEventListener('mousemove', function (e) {
      if (!drag) return;
      tx = drag.tx + (e.clientX - drag.x);
      ty = drag.ty + (e.clientY - drag.y);
      apply();
    });
    window.addEventListener('mouseup', function () {
      drag = null; if (viewport) viewport.classList.remove('grabbing');
    });

    // Zoom (wheel, centered on the cursor).
    viewport.addEventListener('wheel', function (e) {
      e.preventDefault();
      var factor = e.deltaY < 0 ? 1.12 : 0.89;
      zoomAt(factor, e.clientX, e.clientY);
    }, { passive: false });

    viewport.addEventListener('dblclick', function (e) { zoomAt(1.4, e.clientX, e.clientY); });

    // Touch: one finger pans, two fingers pinch-zoom.
    viewport.addEventListener('touchstart', function (e) {
      if (e.touches.length === 1) {
        drag = { x: e.touches[0].clientX, y: e.touches[0].clientY, tx: tx, ty: ty };
      } else if (e.touches.length === 2) {
        drag = null;
        pinch = { dist: touchDist(e), scale: scale, cx: touchMidX(e), cy: touchMidY(e) };
      }
    }, { passive: true });
    viewport.addEventListener('touchmove', function (e) {
      if (pinch && e.touches.length === 2) {
        e.preventDefault();
        var d = touchDist(e);
        var next = clamp(pinch.scale * (d / pinch.dist), MIN, MAX);
        zoomTo(next, pinch.cx, pinch.cy);
      } else if (drag && e.touches.length === 1) {
        tx = drag.tx + (e.touches[0].clientX - drag.x);
        ty = drag.ty + (e.touches[0].clientY - drag.y);
        apply();
      }
    }, { passive: false });
    viewport.addEventListener('touchend', function (e) {
      if (e.touches.length === 0) { drag = null; pinch = null; }
    });

    // Keyboard.
    ov.addEventListener('keydown', function (e) {
      var step = 60;
      if (e.key === 'Escape') close();
      else if (e.key === '+' || e.key === '=') zoomBy(1.25);
      else if (e.key === '-' || e.key === '_') zoomBy(0.8);
      else if (e.key === '0') reset();
      else if (e.key === 'f' || e.key === 'F') fit();
      else if (e.key === 'ArrowLeft')  { tx += step; apply(); }
      else if (e.key === 'ArrowRight') { tx -= step; apply(); }
      else if (e.key === 'ArrowUp')    { ty += step; apply(); }
      else if (e.key === 'ArrowDown')  { ty -= step; apply(); }
      else return;
      e.preventDefault();
    });
    ov.addEventListener('click', function (e) { if (e.target === ov) close(); });
  }

  function touchDist(e) {
    var a = e.touches[0], b = e.touches[1];
    return Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
  }
  function touchMidX(e) { return (e.touches[0].clientX + e.touches[1].clientX) / 2; }
  function touchMidY(e) { return (e.touches[0].clientY + e.touches[1].clientY) / 2; }

  function apply() {
    stage.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
    scaleEl.textContent = Math.round(scale * 100) + '%';
  }
  function zoomBy(f) {
    var r = viewport.getBoundingClientRect();
    zoomAt(f, r.left + r.width / 2, r.top + r.height / 2);
  }
  function zoomAt(f, cx, cy) { zoomTo(clamp(scale * f, MIN, MAX), cx, cy); }
  function zoomTo(next, cx, cy) {
    var r = viewport.getBoundingClientRect();
    var px = cx - r.left, py = cy - r.top;
    // Keep the point under the cursor fixed while scaling.
    tx = px - (px - tx) * (next / scale);
    ty = py - (py - ty) * (next / scale);
    scale = next;
    apply();
  }
  function reset() { scale = 1; centerStage(); }

  // Center the stage content within the viewport at the current scale.
  function centerStage() {
    var vr = viewport.getBoundingClientRect();
    var content = stage.firstElementChild;
    var w = (content && content.getBoundingClientRect().width) || stage.scrollWidth || 0;
    var h = (content && content.getBoundingClientRect().height) || stage.scrollHeight || 0;
    tx = (vr.width - w) / 2;
    ty = (vr.height - h) / 2;
    apply();
  }

  function fit() {
    var vr = viewport.getBoundingClientRect();
    var content = stage.firstElementChild;
    if (!content) { reset(); return; }
    // Measure intrinsic size at scale 1.
    var prev = stage.style.transform;
    stage.style.transform = 'scale(1)';
    var cr = content.getBoundingClientRect();
    stage.style.transform = prev;
    var w = cr.width, h = cr.height;
    if (!w || !h) { reset(); return; }
    var pad = 0.92;
    scale = clamp(Math.min(vr.width / w, vr.height / h) * pad, MIN, MAX);
    centerStage();
  }

  function toggleFull() {
    if (document.fullscreenElement) { document.exitFullscreen(); return; }
    if (ov.requestFullscreen) ov.requestFullscreen().catch(function () {});
  }

  function open(node, opts) {
    if (!node) return;
    opts = opts || {};
    build();
    stage.innerHTML = '';
    var clone = node.cloneNode(true);
    // SVGs scale cleanly; strip any max-width cap so fit/zoom use full extent.
    if (clone.tagName && clone.tagName.toLowerCase() === 'svg') {
      clone.style.maxWidth = 'none'; clone.style.width = ''; clone.style.height = '';
    }
    stage.appendChild(clone);
    ov.querySelector('.kb-canvas-title').textContent = opts.title || '';
    ov.classList.add('open');
    ov.setAttribute('tabindex', '-1');
    ov.focus();
    // Fit on next frame once the clone has laid out.
    requestAnimationFrame(function () { fit(); });
  }

  function close() {
    if (!ov) return;
    if (document.fullscreenElement) { try { document.exitFullscreen(); } catch (e) {} }
    ov.classList.remove('open');
    stage.innerHTML = '';
    scale = 1; tx = 0; ty = 0;
  }

  // Inject a themed "Full view" button into a diagram container. `getNode`
  // returns the node to open (deferred so late-rendered SVGs resolve at click).
  function attachAffordance(container, getNode, opts) {
    if (!container || container.querySelector(':scope > .kb-canvas-open')) return;
    opts = opts || {};
    ensureStyles();
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'kb-canvas-open';
    btn.setAttribute('aria-label', 'Open in full view');
    btn.innerHTML = '<span aria-hidden="true">⤢</span> Full view';
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      var node = typeof getNode === 'function' ? getNode() : getNode;
      if (node) open(node, { title: opts.title || '' });
    });
    container.appendChild(btn);
  }

  window.KBCanvas = {
    open: open,
    close: close,
    attachAffordance: attachAffordance
  };
})();
