/* ──────────────────────────────────────────────────────────────────────────
   KBMedia — shared media component for the client portal template.

   One provider-detecting media component used by BOTH the theater view
   (app/session.html) and the in-place gallery card view (intelligence/). It
   dispatches by media type:

     • video → an embed (iframe for a known player host, or a native <video>
       for a direct media file)
     • image → a lightbox / set viewer with prev/next

   Provider detection + share→embed URL normalization (no provider ID is ever
   hardcoded — the host comes straight from the supplied URL, so empty config
   embeds nothing):

     • YouTube      (youtube.com / youtu.be)              → /embed/<id>
     • Google Drive (drive.google.com, …/d/<ID>/…)         → /file/d/<ID>/preview
     • OneDrive     (onedrive.live.com / 1drv.ms / SharePoint) → ?embed src
     • direct media (.mp4/.webm/.ogg/.mov/.m4v)            → native <video>
     • anything else reachable                            → generic iframe

   Reachability-based with graceful fallback: a non-embeddable link renders a
   thumbnail + "open in new tab" affordance instead.

   Styles live in app/media-player.css (link it on the page). All chrome themes
   off the --kb-* / local-alias seam (theme.css); no palette is hardcoded.

   API:
     KBMedia.resolve(videoUrl, driveUrl?)  -> { kind, src } | null
       kind ∈ 'video' | 'iframe'. Lifted from session.html's resolveVideo, with
       YouTube + OneDrive normalization added.
     KBMedia.playerHtml({video_url, drive_url, thumb, title}) -> html string
       An in-place player: a poster that swaps to the resolved player on click,
       or a thumbnail + open-in-new-tab fallback when nothing is embeddable.
     KBMedia.mount(scopeEl?)               -> wires click-to-play posters in a subtree
     KBMedia.openLightbox(images, index?)  -> open the image set viewer (theater)
       images: [ { src, caption } | "src" ]
     KBMedia.closeLightbox()
   ────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var DIRECT_RE = /\.(mp4|webm|ogg|ogv|mov|m4v)(\?|#|$)/i;

  // ── Provider normalization ────────────────────────────────────────────────
  // Each returns an embeddable iframe src for its host, or null if the URL is
  // not recognized as that provider. Hosts come from the URL itself.
  function youtube(u) {
    var h = u.hostname.replace(/^www\./, '');
    if (h === 'youtu.be') {
      var id = u.pathname.replace(/^\/+/, '').split('/')[0];
      return id ? 'https://www.youtube.com/embed/' + id : null;
    }
    if (h === 'youtube.com' || h === 'youtube-nocookie.com' || h === 'm.youtube.com') {
      if (/^\/embed\//.test(u.pathname)) return u.href;            // already an embed
      var v = u.searchParams.get('v');
      if (v) return 'https://www.youtube.com/embed/' + v;
      var m = u.pathname.match(/^\/(?:shorts|live|v)\/([^/?#]+)/);
      if (m) return 'https://www.youtube.com/embed/' + m[1];
    }
    return null;
  }

  function googleDrive(u) {
    if (!/(^|\.)(drive|docs)\.google\.com$/.test(u.hostname)) return null;
    var m = u.pathname.match(/\/d\/([a-zA-Z0-9_-]+)/);
    if (m) return u.origin + '/file/d/' + m[1] + '/preview';
    if (/\/preview$/.test(u.pathname)) return u.href;
    return null;
  }

  function oneDrive(u) {
    var h = u.hostname.replace(/^www\./, '');
    // Short links and the consumer host: append the documented ?embed flag.
    if (h === '1drv.ms' || h === 'onedrive.live.com') {
      if (u.searchParams.get('embed') === '1' || /\/embed/i.test(u.pathname)) return u.href;
      u.searchParams.set('embed', '1');
      return u.href;
    }
    // SharePoint / OneDrive-for-Business: the ?web=1 doc URL embeds via ?embed=1.
    if (/\.sharepoint\.com$/.test(h)) {
      if (u.searchParams.get('embed') === '1') return u.href;
      u.searchParams.set('embed', '1');
      return u.href;
    }
    return null;
  }

  // Resolve a playable URL into something embeddable. Mirrors the inline
  // resolveVideo() that previously lived in session.html, generalized with
  // YouTube + OneDrive normalization.
  function resolve(videoUrl, driveUrl) {
    var direct = videoUrl && String(videoUrl).trim();
    if (direct) {
      if (DIRECT_RE.test(direct)) return { kind: 'video', src: direct };
      try {
        var u = new URL(direct);
        if (u.protocol === 'https:' || u.protocol === 'http:') {
          var n = youtube(u) || googleDrive(u) || oneDrive(u);
          return { kind: 'iframe', src: n || direct };
        }
      } catch (e) { /* not a URL → fall through */ }
      return { kind: 'iframe', src: direct };
    }
    var drive = driveUrl && String(driveUrl).trim();
    if (drive) {
      try {
        var du = new URL(drive);
        var dn = googleDrive(du) || oneDrive(du) || youtube(du);
        if (dn) return { kind: 'iframe', src: dn };
      } catch (e) { /* fall through to legacy regex */ }
      var m = drive.match(/^(https?:\/\/[^/]+)\/.*\/d\/([a-zA-Z0-9_-]+)/);
      if (m) return { kind: 'iframe', src: m[1] + '/file/d/' + m[2] + '/preview' };
    }
    return null;
  }

  function iframeHtml(src) {
    return '<iframe src="' + esc(src) + '" allow="autoplay; fullscreen" ' +
      'allowfullscreen loading="lazy" referrerpolicy="no-referrer" ' +
      'sandbox="allow-scripts allow-same-origin allow-popups allow-forms allow-presentation"></iframe>';
  }
  function videoHtml(src) {
    return '<video controls preload="metadata" src="' + esc(src) + '"></video>';
  }

  // Build an in-place player. When a poster (thumb) exists the resolved player
  // is lazy: a play button overlays the poster and the iframe/video is only
  // injected on click (no autoplay cost, no early provider hit). Without a
  // poster it renders inline immediately. When nothing is embeddable it falls
  // back to the poster + an open-in-new-tab link (or just the link).
  function playerHtml(opts) {
    opts = opts || {};
    var resolved = resolve(opts.video_url, opts.drive_url);
    var thumb = opts.thumb && String(opts.thumb).trim();
    var title = opts.title || '';

    if (!resolved) {
      var open = (opts.drive_url && String(opts.drive_url).trim()) ||
                 (opts.video_url && String(opts.video_url).trim()) || '';
      var fallbackInner = thumb
        ? '<img src="' + esc(thumb) + '" alt="' + esc(title) + '" loading="lazy">'
        : '<span class="kb-media-ph">' + esc(title || 'Media') + '</span>';
      var link = open
        ? '<a class="kb-media-open" href="' + esc(open) + '" target="_blank" rel="noopener">Open in new tab ↗</a>'
        : '';
      return '<div class="kb-media kb-media-fallback' + (thumb ? '' : ' placeholder') + '">' +
        fallbackInner + link + '</div>';
    }

    var inner = resolved.kind === 'video' ? videoHtml(resolved.src) : iframeHtml(resolved.src);
    if (thumb) {
      // Lazy poster: the player markup is stashed (base64) and injected on click.
      var payload = encodeURIComponent(inner);
      return '<div class="kb-media kb-media-poster" data-kb-player="' + esc(payload) + '" ' +
        'tabindex="0" role="button" aria-label="Play ' + esc(title || 'media') + '">' +
        '<img src="' + esc(thumb) + '" alt="' + esc(title) + '" loading="lazy">' +
        '<span class="kb-media-play" aria-hidden="true">▶</span>' +
        '</div>';
    }
    return '<div class="kb-media">' + inner + '</div>';
  }

  // Swap a poster for its stashed player. Used by both the click handler and
  // keyboard activation (Enter/Space).
  function activatePoster(el) {
    var payload = el.getAttribute('data-kb-player');
    if (!payload) return;
    el.classList.remove('kb-media-poster');
    el.removeAttribute('data-kb-player');
    el.removeAttribute('role');
    el.removeAttribute('tabindex');
    try { el.innerHTML = decodeURIComponent(payload); } catch (e) { /* leave poster */ }
  }

  // Wire click-to-play posters within a subtree (idempotent via a data flag).
  function mount(scope) {
    scope = scope || document;
    if (scope.getAttribute && scope.getAttribute('data-kb-media-mounted')) return;
    var handler = function (e) {
      var el = e.target.closest && e.target.closest('.kb-media-poster');
      if (!el) return;
      if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
      if (e.type === 'keydown') e.preventDefault();
      activatePoster(el);
    };
    var root = (scope.addEventListener ? scope : document);
    root.addEventListener('click', handler);
    root.addEventListener('keydown', handler);
    if (scope.setAttribute) scope.setAttribute('data-kb-media-mounted', '1');
  }

  // ── Image lightbox / set viewer (theater) ─────────────────────────────────
  // A reusable full-screen image viewer with prev/next across a set. Generalizes
  // session.html's single-image lightbox. Built lazily on first open.
  var lb = null, lbImg, lbCap, lbCounter, lbSet = [], lbIdx = 0;

  function buildLightbox() {
    if (lb) return;
    lb = document.createElement('div');
    lb.className = 'kb-lightbox';
    lb.setAttribute('role', 'dialog');
    lb.setAttribute('aria-modal', 'true');
    lb.innerHTML =
      '<button class="kb-lb-close" type="button" aria-label="Close">✕</button>' +
      '<button class="kb-lb-nav kb-lb-prev" type="button" aria-label="Previous">‹</button>' +
      '<img class="kb-lb-img" src="" alt="">' +
      '<button class="kb-lb-nav kb-lb-next" type="button" aria-label="Next">›</button>' +
      '<div class="kb-lb-caption"></div>' +
      '<div class="kb-lb-counter"></div>';
    document.body.appendChild(lb);
    lbImg = lb.querySelector('.kb-lb-img');
    lbCap = lb.querySelector('.kb-lb-caption');
    lbCounter = lb.querySelector('.kb-lb-counter');
    lb.querySelector('.kb-lb-close').addEventListener('click', closeLightbox);
    lb.querySelector('.kb-lb-prev').addEventListener('click', function () { step(-1); });
    lb.querySelector('.kb-lb-next').addEventListener('click', function () { step(1); });
    lb.addEventListener('click', function (e) { if (e.target === lb) closeLightbox(); });
    document.addEventListener('keydown', function (e) {
      if (!lb.classList.contains('open')) return;
      if (e.key === 'Escape') closeLightbox();
      else if (e.key === 'ArrowLeft') step(-1);
      else if (e.key === 'ArrowRight') step(1);
    });
  }

  function showFrame() {
    var item = lbSet[lbIdx] || {};
    lbImg.src = item.src || '';
    lbImg.alt = item.caption || '';
    lbCap.textContent = item.caption || '';
    var many = lbSet.length > 1;
    lbCounter.textContent = many ? (lbIdx + 1) + ' / ' + lbSet.length : '';
    lb.querySelector('.kb-lb-prev').style.display = many ? '' : 'none';
    lb.querySelector('.kb-lb-next').style.display = many ? '' : 'none';
  }
  function step(d) {
    if (!lbSet.length) return;
    lbIdx = (lbIdx + d + lbSet.length) % lbSet.length;
    showFrame();
  }
  function openLightbox(images, index) {
    buildLightbox();
    lbSet = (Array.isArray(images) ? images : [images]).map(function (it) {
      return typeof it === 'string' ? { src: it, caption: '' } : (it || {});
    }).filter(function (it) { return it.src; });
    if (!lbSet.length) return;
    lbIdx = Math.max(0, Math.min(index || 0, lbSet.length - 1));
    showFrame();
    lb.classList.add('open');
  }
  function closeLightbox() {
    if (!lb) return;
    lb.classList.remove('open');
    lbImg.src = '';
    lbSet = [];
  }

  window.KBMedia = {
    resolve: resolve,
    playerHtml: playerHtml,
    mount: mount,
    activatePoster: activatePoster,
    openLightbox: openLightbox,
    closeLightbox: closeLightbox,
    esc: esc
  };

  // Auto-wire posters present at load (pages that inject later call mount again).
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { mount(document); });
  } else {
    mount(document);
  }
})();
