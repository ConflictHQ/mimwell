// Client portal chat bubble — injected into every HTML page by worker.js.
// Talks to POST /api/chat; renders replies + navigation chips.
//
// Branding (accent colors, fonts, labels, greeting) is read from
// /client.config.json at startup and exposed as --kb-* CSS custom properties;
// the stylesheet references those vars so nothing here is client-specific.
//
// The neutral SURFACE/TEXT vars instead flip with the active light/dark theme
// (data-theme on <html>, managed by app/theme.js) so the bubble matches the
// page in both palettes while keeping the client's brand accent. Per-theme
// neutrals are defined in CSS keyed off data-theme, so the flip is automatic.
// Those neutrals live in a BUBBLE-PRIVATE --kbb-* namespace (not the page's
// shared --kb-* seam) — see the note at THEME_VARS for why.
//
// User settings (theme + chat answer-mode) persist in a single shared cookie
// (kb_prefs, URL-encoded JSON) that app/theme.js also writes, so the worker can
// read them server-side and paint the right theme before paint. The cookie
// carries no PII. A visibilitychange re-sync picks up changes made in another
// tab (cookies don't fire the storage event).
(function () {
  if (window.__kbBubble) return;
  window.__kbBubble = true;

  // ── Shared cookie prefs (mirrors app/theme.js) ────────────────────────────
  function readPrefs() {
    try {
      var m = document.cookie.match(/(?:^|;\s*)kb_prefs=([^;]*)/);
      if (!m) return {};
      var o = JSON.parse(decodeURIComponent(m[1]));
      return (o && typeof o === "object") ? o : {};
    } catch (e) { return {}; }
  }

  function writePref(key, value) {
    try {
      var prefs = readPrefs();
      prefs[key] = value;
      document.cookie = "kb_prefs=" +
        encodeURIComponent(JSON.stringify(prefs)) +
        ";path=/;max-age=31536000;SameSite=Lax";
    } catch (e) { /* cookies disabled */ }
  }

  // Sane defaults mirroring client.config.json's branding schema, used if the
  // config fetch fails so the bubble still renders and works. Only the accent
  // (primary/link) and fonts come from config; surface/text neutrals are
  // theme-driven (see THEME_VARS below).
  const DEFAULT_CONFIG = {
    branding: {
      colors: {
        primary: "#1E9C8F",
        link: "#2F97BF",
      },
      fonts: {
        heading: "'Fraunces', Georgia, serif",
        body: "'Inter', system-ui, sans-serif",
        mono: "'JetBrains Mono', monospace",
      },
      headerLabel: "KNOWLEDGE BASE",
      headerSub: "knowledge base agent",
      greeting:
        "Ask me anything about the engagement — decisions, data sources, open questions, the plan. I answer from the portal knowledge base.",
      inputPlaceholder: "Ask about the project…",
    },
  };

  async function loadConfig() {
    try {
      const resp = await fetch("/client.config.json");
      if (!resp.ok) return DEFAULT_CONFIG;
      const cfg = await resp.json();
      return cfg && cfg.branding ? cfg : DEFAULT_CONFIG;
    } catch {
      return DEFAULT_CONFIG;
    }
  }

  // Neutral surface/text vars for each theme. These drive the bubble's
  // backgrounds and text so it tracks the page's light/dark palette (mirroring
  // app/theme.css's local-alias values); the brand accent stays config-driven.
  // Derived tints reference these via color-mix so they flip automatically too.
  // NOTE: these are a BUBBLE-PRIVATE namespace (--kbb-*), deliberately NOT the
  // page's --kb-* seam. The portal pages pin every --kb-* neutral as an INLINE
  // style on <html> (root.style.setProperty from client.config.json), and inline
  // styles beat any stylesheet rule at any specificity — so a bubble rule keyed
  // on :root[data-theme] could never override them and the bubble stayed locked
  // to one palette. Owning private neutrals lets the per-theme blocks below win
  // cleanly and flip the bubble with the page. Brand accent (--kb-primary/link)
  // and fonts stay on the shared seam — those SHOULD track the pinned brand.
  const THEME_VARS = {
    light: `
      --kbb-bg:#FFFFFF;
      --kbb-bg-deep:#F4F5F8;
      --kbb-surface:#EDEFF5;
      --kbb-border:#E2E8F0;
      --kbb-border-light:#D7DEEC;
      --kbb-text:#231F20;
      --kbb-text-muted:#56575D;
      --kbb-text-faint:#86868B;
      --kbb-strong:#000000;`,
    dark: `
      --kbb-bg:#0B1619;
      --kbb-bg-deep:#060D0F;
      --kbb-surface:#0F1E22;
      --kbb-border:#1D3238;
      --kbb-border-light:#27414A;
      --kbb-text:#F8F8F8;
      --kbb-text-muted:#888888;
      --kbb-text-faint:#555555;
      --kbb-strong:#FFFFFF;`,
  };

  function init(config) {
    const b = config.branding;
    const c = b.colors;
    const f = b.fonts;

    // Config "seam" + derived vars: brand accent and fonts only. Neutral
    // surface/text vars live in the per-theme blocks below so they flip with
    // data-theme; tints derive from whichever neutral is active at the time.
    const seam = `
      --kb-primary:${c.primary};
      --kb-link:${c.link};
      --kb-font-heading:${f.heading};
      --kb-font-body:${f.body};
      --kb-font-mono:${f.mono};
      --kb-chip-bg:color-mix(in srgb, var(--kb-primary) 12%, transparent);
      --kb-chip-bg-hover:color-mix(in srgb, var(--kb-primary) 25%, transparent);
      --kb-chip-border:color-mix(in srgb, var(--kb-primary) 45%, transparent);
      --kb-mode-bg:color-mix(in srgb, var(--kbb-bg) 92%, var(--kbb-text));
      --kb-code-bg:color-mix(in srgb, var(--kbb-surface) 88%, var(--kbb-text));
      --kbb-text-dim:color-mix(in srgb, var(--kbb-text-faint) 70%, var(--kbb-bg));`;

    // Default neutrals on :root (used before data-theme is set or if theme.css
    // is absent), then per-theme overrides at higher specificity that win when
    // <html data-theme> flips — so the bubble reskins with no JS re-render.
    const vars = `
    :root { ${seam}${THEME_VARS.dark} }
    :root[data-theme="light"] { ${THEME_VARS.light} }
    :root[data-theme="dark"] { ${THEME_VARS.dark} }`;

    const css = `
  #kb-bubble-btn { position:fixed; bottom:22px; right:22px; z-index:9999; width:52px; height:52px;
    border-radius:50%; background:var(--kb-primary); border:none; cursor:pointer; box-shadow:0 4px 18px rgba(0,0,0,.45);
    display:flex; align-items:center; justify-content:center; transition:transform .15s; }
  #kb-bubble-btn:hover { transform:scale(1.07); }
  #kb-bubble-btn svg { width:24px; height:24px; fill:#fff; }
  #kb-chat { position:fixed; bottom:86px; right:22px; z-index:9999; width:380px; max-width:calc(100vw - 44px);
    height:520px; max-height:calc(100vh - 130px); background:var(--kbb-bg); border:1px solid var(--kbb-border-light); border-radius:10px;
    display:none; flex-direction:column; overflow:hidden; box-shadow:0 10px 40px rgba(0,0,0,.6);
    font-family:var(--kb-font-body); font-size:13px; color:var(--kbb-text); transition:width .15s, height .15s; }
  #kb-chat.open { display:flex; }
  #kb-chat.max { width:calc(100vw - 44px); height:calc(100vh - 130px); max-width:1100px; }
  #kb-chat.max .kb-msg { max-width:760px; font-size:14px; }
  #kb-chat-expand { background:none; border:none; color:var(--kbb-text-muted); font-size:14px; cursor:pointer; margin-right:6px; }
  #kb-chat-expand:hover, #kb-chat-close:hover { color:var(--kbb-text); }
  #kb-chat-mode { background:var(--kb-mode-bg); border:1px solid var(--kbb-border-light); border-radius:10px; color:var(--kbb-text-muted); font-size:10px;
    font-family:var(--kb-font-mono); text-transform:uppercase; letter-spacing:.05em; cursor:pointer;
    padding:2px 9px; margin-right:8px; }
  #kb-chat-mode:hover { color:var(--kbb-text); border-color:var(--kbb-text-faint); }
  #kb-chat-head { padding:10px 14px; background:var(--kbb-bg-deep); border-bottom:1px solid var(--kbb-border); display:flex;
    justify-content:space-between; align-items:center; }
  #kb-chat-head b { font-family:var(--kb-font-heading); font-weight:400; letter-spacing:.08em; color:var(--kb-primary);
    text-transform:uppercase; font-size:13px; }
  #kb-chat-head small { color:var(--kbb-text-faint); font-size:10px; margin-left:8px; }
  #kb-chat-close { background:none; border:none; color:var(--kbb-text-muted); font-size:16px; cursor:pointer; }
  #kb-chat-log { flex:1; overflow-y:auto; padding:14px; display:flex; flex-direction:column; gap:10px; }
  .kb-msg { max-width:88%; padding:8px 11px; border-radius:8px; line-height:1.55; word-wrap:break-word; }
  .kb-msg.user { align-self:flex-end; background:var(--kbb-border); white-space:pre-wrap; }
  .kb-msg.bot { align-self:flex-start; background:var(--kbb-surface); border:1px solid var(--kbb-border); }
  .kb-msg.bot.thinking { color:var(--kbb-text-faint); font-style:italic; }
  .kb-msg.bot p { margin:0 0 8px; } .kb-msg.bot p:last-child { margin-bottom:0; }
  .kb-msg.bot h4 { font-family:var(--kb-font-heading); font-weight:400; font-size:13px; letter-spacing:.06em;
    text-transform:uppercase; color:var(--kb-primary); margin:12px 0 6px; }
  .kb-msg.bot ul, .kb-msg.bot ol { margin:0 0 8px; padding-left:20px; }
  .kb-msg.bot li { margin-bottom:3px; }
  .kb-msg.bot hr { border:none; border-top:1px solid var(--kbb-border); margin:10px 0; }
  .kb-msg.bot code { font-family:var(--kb-font-mono); font-size:11px; background:var(--kb-code-bg);
    border:1px solid var(--kbb-border); border-radius:3px; padding:0 4px; }
  .kb-msg.bot strong { color:var(--kbb-strong); }
  .kb-msg.bot em { font-style:italic; }
  .kb-msg.bot table { display:block; overflow-x:auto; border-collapse:collapse; margin:2px 0 10px; font-size:12px; }
  .kb-msg.bot th, .kb-msg.bot td { border:1px solid var(--kbb-border); padding:4px 9px; text-align:left; vertical-align:top; }
  .kb-msg.bot th { background:var(--kbb-bg-deep); color:var(--kbb-strong); font-weight:600; white-space:nowrap; }
  .kb-chips { display:flex; gap:6px; flex-wrap:wrap; align-self:flex-start; }
  .kb-chip { font-size:11px; color:var(--kbb-text); background:var(--kb-chip-bg); border:1px solid var(--kb-chip-border);
    border-radius:14px; padding:3px 11px; cursor:pointer; text-decoration:none; }
  .kb-chip:hover { background:var(--kb-chip-bg-hover); }
  .kb-sources { align-self:flex-start; max-width:88%; border-left:2px solid var(--kbb-border); padding:2px 0 2px 10px; }
  .kb-sources b { display:block; font-family:var(--kb-font-mono); font-size:9px; font-weight:700;
    text-transform:uppercase; letter-spacing:.08em; color:var(--kbb-text-faint); margin-bottom:3px; }
  .kb-sources a { display:block; font-family:var(--kb-font-mono); font-size:10px; color:var(--kb-link);
    text-decoration:none; line-height:1.7; }
  .kb-sources a:hover { color:var(--kbb-text); }
  #kb-chat-form { display:flex; border-top:1px solid var(--kbb-border); }
  #kb-chat-input { flex:1; background:var(--kbb-bg-deep); border:none; outline:none; color:var(--kbb-text); padding:11px 13px;
    font-family:inherit; font-size:13px; }
  #kb-chat-send { background:none; border:none; color:var(--kb-primary); font-weight:700; cursor:pointer; padding:0 14px;
    font-size:12px; letter-spacing:.05em; }
  #kb-chat-send:disabled { color:var(--kbb-text-dim); cursor:default; }`;

    const style = document.createElement("style");
    style.textContent = vars + css;
    document.head.appendChild(style);

    const btn = document.createElement("button");
    btn.id = "kb-bubble-btn";
    btn.title = "Ask the knowledge base";
    btn.innerHTML =
      '<svg viewBox="0 0 24 24"><path d="M12 3C7 3 3 6.6 3 11c0 2.2 1 4.2 2.7 5.6L5 21l4-1.6c.9.3 1.9.4 3 .4 5 0 9-3.6 9-8s-4-8.8-9-8.8z"/></svg>';
    document.body.appendChild(btn);

    const panel = document.createElement("div");
    panel.id = "kb-chat";
    panel.innerHTML = `
      <div id="kb-chat-head"><div><b></b><small></small></div>
        <div><button id="kb-chat-mode" title="Answer depth — click to cycle"></button><button id="kb-chat-expand" aria-label="Expand" title="Expand">⛶</button><button id="kb-chat-close" aria-label="Close">✕</button></div></div>
      <div id="kb-chat-log"></div>
      <form id="kb-chat-form"><input id="kb-chat-input" autocomplete="off"/>
        <button id="kb-chat-send" type="submit">SEND</button></form>`;
    document.body.appendChild(panel);

    // Header label/sub, input placeholder come from config; set as text/attrs
    // (never via innerHTML) so client values can't inject markup.
    panel.querySelector("#kb-chat-head b").textContent = b.headerLabel;
    panel.querySelector("#kb-chat-head small").textContent = b.headerSub;
    panel.querySelector("#kb-chat-input").placeholder = b.inputPlaceholder;

    const log = panel.querySelector("#kb-chat-log");
    const input = panel.querySelector("#kb-chat-input");
    const send = panel.querySelector("#kb-chat-send");
    const history = [];

    const MODES = ["terse", "brief", "standard", "deep", "academic"];
    const modeBtn = panel.querySelector("#kb-chat-mode");
    let mode = readPrefs().mode || "standard";
    if (!MODES.includes(mode)) mode = "standard";
    modeBtn.textContent = mode;
    modeBtn.addEventListener("click", () => {
      mode = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
      writePref("mode", mode);
      modeBtn.textContent = mode;
      input.focus();
    });

    // Minimal markdown -> HTML for bot messages. Escapes all HTML first, then
    // renders: ## headings, **bold**, *italic*, \`code\`, - / 1. lists,
    // GFM | tables |, and --- dividers.
    function md(text) {
      const esc = String(text).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
      // Bold first so ** is consumed before the single-* italic rule sees it.
      const inline = (s) =>
        s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
         .replace(/(^|[^*\w])\*(?!\s)([^*]+?)\*(?!\w)/g, "$1<em>$2</em>")
         .replace(/(^|[^_\w])_(?!\s)([^_]+?)_(?!\w)/g, "$1<em>$2</em>")
         .replace(/`([^`]+)`/g, "<code>$1</code>");
      const cells = (row) => row.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const out = [];
      let list = null, listTag = "ul", para = [];
      const flushPara = () => { if (para.length) { out.push(`<p>${para.join("<br>")}</p>`); para = []; } };
      const flushList = () => { if (list) { out.push(`<${listTag}>${list.join("")}</${listTag}>`); list = null; } };
      const lines = esc.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) { flushPara(); flushList(); continue; }
        // GFM table: a header row, then a |---|---| separator (pipes + dashes),
        // then contiguous | rows. The separator's pipe requirement keeps a bare
        // --- divider from being mistaken for a one-column table.
        const next = (lines[i + 1] || "").trim();
        if (line.includes("|") && next.includes("|") && next.includes("-") && /^[\s:|-]+$/.test(next)) {
          flushPara(); flushList();
          const head = cells(line);
          const body = [];
          let j = i + 2;
          while (j < lines.length && lines[j].trim().includes("|") && lines[j].trim()) { body.push(cells(lines[j])); j++; }
          const th = head.map((c) => `<th>${inline(c)}</th>`).join("");
          const trs = body.map((r) => `<tr>${head.map((_, k) => `<td>${inline(r[k] || "")}</td>`).join("")}</tr>`).join("");
          out.push(`<table><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table>`);
          i = j - 1;
          continue;
        }
        if (/^-{3,}$/.test(line)) { flushPara(); flushList(); out.push("<hr>"); continue; }
        const h = line.match(/^#{1,4}\s+(.*)$/);
        if (h) { flushPara(); flushList(); out.push(`<h4>${inline(h[1])}</h4>`); continue; }
        const ol = line.match(/^\d+[.)]\s+(.*)$/);
        const ul = ol ? null : line.match(/^[-*•]\s+(.*)$/);
        if (ol || ul) {
          const tag = ol ? "ol" : "ul";
          if (list && listTag !== tag) flushList();
          flushPara();
          listTag = tag;
          (list = list || []).push(`<li>${inline((ol || ul)[1])}</li>`);
          continue;
        }
        flushList(); para.push(inline(line));
      }
      flushPara(); flushList();
      return out.join("");
    }

    function add(role, text, cls) {
      const div = document.createElement("div");
      div.className = `kb-msg ${role}${cls ? " " + cls : ""}`;
      if (role === "bot" && !cls) div.innerHTML = md(text);
      else div.textContent = text;
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
      return div;
    }

    function addChips(actions) {
      if (!actions || !actions.length) return;
      const wrap = document.createElement("div");
      wrap.className = "kb-chips";
      for (const a of actions.slice(0, 3)) {
        const chip = document.createElement("a");
        chip.className = "kb-chip";
        chip.textContent = a.label + " →";
        chip.href = a.url;
        wrap.appendChild(chip);
      }
      log.appendChild(wrap);
      log.scrollTop = log.scrollHeight;
    }

    function addSources(sources) {
      if (!sources || !sources.length) return;
      const wrap = document.createElement("div");
      wrap.className = "kb-sources";
      const head = document.createElement("b");
      head.textContent = "Sources";
      wrap.appendChild(head);
      for (const s of sources) {
        const a = document.createElement("a");
        a.textContent = s.title + " — " + s.path;
        a.href = s.path.endsWith(".md") ? "/app/reader.html?f=" + encodeURIComponent(s.path) : "/" + s.path;
        a.target = "_blank";
        wrap.appendChild(a);
      }
      log.appendChild(wrap);
      log.scrollTop = log.scrollHeight;
    }

    log.setAttribute('role', 'log'); log.setAttribute('aria-live', 'polite');
    window.addEventListener('kb-ask', (event) => {
      panel.classList.add('open');
      if (!log.children.length) add('bot', b.greeting);
      // Opening Ask must not overwrite an unsent chat draft.
      if (!input.value && event.detail && typeof event.detail.question === 'string') input.value = event.detail.question;
      input.focus();
    });
    btn.addEventListener("click", () => {
      panel.classList.toggle("open");
      if (panel.classList.contains("open")) {
        if (!log.children.length) add("bot", b.greeting);
        input.focus();
      }
    });
    panel.querySelector("#kb-chat-close").addEventListener("click", () => panel.classList.remove("open"));
    panel.querySelector("#kb-chat-expand").addEventListener("click", () => {
      panel.classList.toggle("max");
      log.scrollTop = log.scrollHeight;
      input.focus();
    });

    panel.querySelector("#kb-chat-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q || send.disabled) return;
      input.value = "";
      add("user", q);
      history.push({ role: "user", content: q });
      send.disabled = true;
      const pending = add("bot", "Searching the knowledge base…", "thinking");
      try {
        const resp = await fetch("/api/chat", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ messages: history, mode }),
        });
        const data = await resp.json();
        pending.remove();
        if (!resp.ok || data.error) {
          add("bot", "Error: " + (data.error || resp.status));
        } else {
          add("bot", data.reply);
          addSources(data.sources);
          addChips(data.actions);
          history.push({ role: "assistant", content: data.reply });
        }
      } catch (err) {
        pending.remove();
        add("bot", "Network error — try again.");
      } finally {
        send.disabled = false;
        input.focus();
      }
    });
  }

  // Keep the bubble in sync with the active light/dark theme. The per-theme CSS
  // blocks reskin the bubble automatically whenever <html data-theme> changes,
  // so we only need to make sure that attribute reflects the current choice:
  //   - seed it from the cookie / OS preference if theme.js hasn't run yet
  //     (and the worker didn't already stamp data-theme);
  //   - mirror cross-tab changes — cookies do NOT fire the storage event, so we
  //     re-read on visibilitychange (when the tab is shown again).
  const rootEl = document.documentElement;

  function osTheme() {
    return window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }

  function storedTheme() {
    const v = readPrefs().theme;
    return v === "light" || v === "dark" ? v : null;
  }

  function syncTheme() {
    const t = storedTheme() || osTheme();
    if (rootEl.getAttribute("data-theme") !== t) {
      rootEl.setAttribute("data-theme", t);
    }
  }

  // Seed the attribute if nothing set it yet (e.g. theme.js + worker absent),
  // then re-sync from the cookie when this tab regains focus so a toggle made
  // in another tab takes effect here too.
  if (!rootEl.getAttribute("data-theme")) syncTheme();
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && storedTheme()) syncTheme();
  });

  // Await branding config, then build the UI (defaults on failure).
  (async () => {
    const config = await loadConfig();
    init(config);
  })();
})();
