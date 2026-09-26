// Client portal authoring UI (#38) — the in-portal editor. Injected into every
// HTML page by worker.js ONLY when features.authoring is on (default off => this
// file is never loaded and the portal stays read-only). Mirrors app/bubble.js:
// an IIFE, fetches /client.config.json at startup, config-driven, no client
// literals.
//
// Three input surfaces, all converging on the SAME validated write path
// (POST /api/edit -> draft/diff -> explicit operator save -> GitHub commit):
//
//   1. SCHEMA-DRIVEN FORMS — generated from the JSON Schema registry under
//      /schemas/*.schema.json. The editable types derive from the compiled
//      ontology (app/kinds.json: x-conflict.editable, a records collection and a
//      mutability tier other than anchor — the same rule worker.js applies); the
//      form fields are driven off the schema's properties, so adding an artifact
//      type needs no new UI. (#21 registry)
//   2. JSON MODE — a raw editor for the same record. Live validation against
//      the fetched schema (parse errors name line and column); preview and save
//      are BLOCKED while invalid.
//   3. PROSE / buffer — a markdown buffer for one text field of the record with
//      the embedded edit-agent (rewrite/expand/summarize on the selection); the
//      agent returns markdown into the buffer and NEVER commits — "Apply to
//      record" copies the buffer into the record, and the operator saves
//      through the validated path.
//
// A brain whose records live in a declared store authority is not edited here:
// the panel points at that authority's governed writer (the knowledge
// workbench) and the write calls refuse, matching the Worker.
//
// Edit lifecycle for forms/JSON: build typed ops -> validate client-side ->
// POST {action:"draft", ops} -> render the returned diff -> operator clicks Save
// -> POST {action:"commit", files}. Conversational/agent edits are gated by
// features.authoring_agent; the buffer edit-agent by features.authoring_wysiwyg /
// authoring_wysiwyg_agent. Nothing auto-commits.
(function () {
  if (window.__kbEditor) return;
  window.__kbEditor = true;

  var CONFIG = null;
  var FEATURES = {};
  // schema-name -> parsed schema (lazy-loaded from /schemas/).
  var SCHEMA_CACHE = {};

  // Editable artifacts, keyed by the type the /api/edit tools expect (the source
  // file's basename, which is also its schema name). Derived from app/kinds.json
  // by the same rule as worker.js editableArtifacts(); empty until loaded, so an
  // unknown or anchor kind is rejected.
  var ARTIFACTS = {};

  function loadConfig() {
    return fetch("/client.config.json")
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; });
  }

  function loadArtifacts() {
    return fetch("/app/kinds.json")
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; })
      .then(function (doc) {
        var out = {};
        ((doc && doc.kinds) || []).forEach(function (k) {
          if (k.editable !== true || k.mutability === "anchor" || !k.records) return;
          var m = /^app\/([a-z0-9-]+)\.json$/.exec(k.artifact || "");
          if (!m) return;
          out[m[1]] = { path: k.artifact, collection: k.records, schema: m[1], kind: k.id, title: k.title || m[1] };
        });
        return out;
      });
  }

  // A declared store authority owns its records; this editor never writes it.
  function authority() { return CONFIG && CONFIG.brain && CONFIG.brain.authority; }

  // Fetch + cache a schema by registry name. Schemas are served as static assets
  // (only worker.js/wrangler.toml/*.db are .assetsignore'd), so the editor reads
  // them client-side — no new endpoint.
  function loadSchema(name) {
    if (SCHEMA_CACHE[name]) return Promise.resolve(SCHEMA_CACHE[name]);
    return fetch("/schemas/" + name + ".schema.json")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { SCHEMA_CACHE[name] = s; return s; })
      .catch(function () { return null; });
  }

  // Resolve the per-record schema (the `items` schema of the editable
  // collection) so forms + JSON validation operate on a single record.
  function recordSchema(schema, collection) {
    if (!schema || !schema.properties) return null;
    var coll = schema.properties[collection];
    if (!coll || coll.type !== "array" || !coll.items) return null;
    var items = coll.items;
    if (items.$ref && items.$ref.indexOf("#/$defs/") === 0) items = (schema.$defs || {})[items.$ref.slice(8)] || null;
    return items;
  }

  // A record's identity, by the same field order worker.js findRecordIndex uses.
  var ID_FIELDS = ["id", "title", "term", "name", "question", "text", "product"];
  function recordId(rec) {
    for (var i = 0; i < ID_FIELDS.length; i++) {
      if (rec && rec[ID_FIELDS[i]] != null && rec[ID_FIELDS[i]] !== "") return String(rec[ID_FIELDS[i]]);
    }
    return null;
  }

  // Form field values -> record. Each field is {name, kind, value}; kind is
  // "text", "number", "boolean" ("", "true", "false"), "list" (one string per
  // line) or "json" (a nested object or object list). Empty values are omitted.
  // Returns {record, errors}.
  function recordFromFields(fields) {
    var rec = {};
    var errors = [];
    fields.forEach(function (f) {
      var v = f.value == null ? "" : String(f.value);
      if (v.trim() === "") return;
      if (f.kind === "number") {
        if (isNaN(Number(v))) errors.push(f.name + " must be a number");
        else rec[f.name] = Number(v);
      } else if (f.kind === "boolean") {
        rec[f.name] = v === "true";
      } else if (f.kind === "list") {
        rec[f.name] = v.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
      } else if (f.kind === "json") {
        try { rec[f.name] = JSON.parse(v); } catch (e) { errors.push(f.name + ": " + e.message); }
      } else {
        rec[f.name] = v;
      }
    });
    return { record: rec, errors: errors };
  }

  // The offset of the first syntax error in `text`, found by scanning it: engines
  // word JSON.parse errors differently and many omit the position (V8's
  // "Unexpected token" and "Unexpected end" messages; Safari always).
  function jsonErrorOffset(text) {
    var i = 0;
    function fail() { throw { at: i }; }
    function ws() { while (i < text.length && " \t\n\r".indexOf(text[i]) >= 0) i++; }
    function word(w) {
      for (var j = 0; j < w.length; j++, i++) if (text[i] !== w[j]) fail();
    }
    function str() {
      i++;
      while (text[i] !== '"') {
        if (i >= text.length || text.charCodeAt(i) < 0x20) fail();
        if (text[i] === "\\") {
          i++;
          if (text[i] === "u") {
            i++;
            for (var j = 0; j < 4; j++, i++) if (!/[0-9a-fA-F]/.test(text[i] || "")) fail();
            continue;
          }
          if (i >= text.length || '"\\/bfnrt'.indexOf(text[i]) < 0) fail();
        }
        i++;
      }
      i++;
    }
    function value() {
      ws();
      var c = text[i];
      if (c === "{" || c === "[") {
        var close = c === "{" ? "}" : "]";
        i++; ws();
        if (text[i] === close) { i++; return; }
        for (;;) {
          if (c === "{") {
            ws();
            if (text[i] !== '"') fail();
            str(); ws();
            if (text[i] !== ":") fail();
            i++;
          }
          value(); ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === close) { i++; return; }
          fail();
        }
      }
      if (c === '"') return str();
      if (c === "t") return word("true");
      if (c === "f") return word("false");
      if (c === "n") return word("null");
      var m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
      if (!m) fail();
      i += m[0].length;
    }
    try { value(); ws(); if (i < text.length) fail(); } catch (e) { if (e && typeof e.at === "number") return e.at; throw e; }
    return null;
  }

  // JSON-mode text -> record. A parse error names its line and column.
  function recordFromJson(text) {
    var rec;
    try {
      rec = JSON.parse(text);
    } catch (e) {
      var detail = e.message.replace(/ at position \d+( \(line \d+ column \d+\))?/, "");
      var at = jsonErrorOffset(text);
      if (at == null) return { record: null, errors: ["JSON: " + detail] };
      var lines = text.slice(0, at).split("\n");
      return { record: null, errors: ["JSON: line " + lines.length + ", column " + (lines[lines.length - 1].length + 1) + ": " + detail] };
    }
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) return { record: null, errors: ["JSON: expected one record object"] };
    return { record: rec, errors: [] };
  }

  // One typed op from an edited record: add_record for a new record, otherwise
  // update_record carrying only the changed fields, plus `unset` naming the
  // fields the edit cleared (`derived` is the Worker's provenance mark, not an
  // authored field). Every surface builds its op here, so the same edit yields
  // the same op whichever surface produced it.
  function buildOp(type, original, record) {
    if (!original) return { op: "add_record", type: type, data: record };
    var fields = {};
    Object.keys(record).forEach(function (k) {
      if (JSON.stringify(record[k]) !== JSON.stringify(original[k])) fields[k] = record[k];
    });
    var op = { op: "update_record", type: type, id: recordId(original), fields: fields };
    var unset = Object.keys(original).filter(function (k) { return k !== "derived" && !Object.prototype.hasOwnProperty.call(record, k); });
    if (unset.length) op.unset = unset;
    return op;
  }

  // --- Minimal client-side schema validation (#21 live-validation seam) -------
  // Validates ONE record against its item schema; enough to block an invalid
  // commit (required keys, primitive types, enums, additionalProperties:false).
  // A power-user JSON editor would bind CodeMirror/Monaco to the same schema; the
  // commit gate here is the contract the issue requires ("blocks commit on
  // invalid"). Returns a list of error strings (empty == valid).
  function validateRecord(rec, schema) {
    var errors = [];
    if (!schema || typeof schema !== "object") return errors;
    if (schema.type === "object" || schema.properties) {
      if (rec === null || typeof rec !== "object" || Array.isArray(rec)) {
        return ["expected an object"];
      }
      var props = schema.properties || {};
      (schema.required || []).forEach(function (k) {
        if (rec[k] === undefined || rec[k] === null || rec[k] === "") {
          errors.push("missing required field: " + k);
        }
      });
      if (schema.additionalProperties === false) {
        Object.keys(rec).forEach(function (k) {
          if (k !== "derived" && !props[k]) errors.push("unknown field: " + k);
        });
      }
      Object.keys(props).forEach(function (k) {
        if (rec[k] === undefined) return;
        errors = errors.concat(validateValue(rec[k], props[k], k));
      });
    }
    return errors;
  }

  function validateValue(val, schema, path) {
    var errors = [];
    if (!schema || typeof schema !== "object") return errors;
    var t = schema.type;
    if (t === "string" && typeof val !== "string") errors.push(path + " must be a string");
    if (t === "integer" && (typeof val !== "number" || val % 1 !== 0)) errors.push(path + " must be an integer");
    if (t === "number" && typeof val !== "number") errors.push(path + " must be a number");
    if (t === "boolean" && typeof val !== "boolean") errors.push(path + " must be a boolean");
    if (t === "array" && !Array.isArray(val)) errors.push(path + " must be an array");
    if (schema.enum && schema.enum.indexOf(val) < 0) {
      errors.push(path + " must be one of: " + schema.enum.join(", "));
    }
    if (typeof val === "string" && schema.minLength && val.length < schema.minLength) {
      errors.push(path + " is too short");
    }
    if (t === "array" && Array.isArray(val) && schema.items) {
      val.forEach(function (v, i) { errors = errors.concat(validateValue(v, schema.items, path + "[" + i + "]")); });
    }
    return errors;
  }

  // --- /api/edit calls --------------------------------------------------------
  function postEdit(payload) {
    if (authority() && payload.action !== "buffer") {
      return Promise.reject(new Error("Records are held by the declared authority; propose changes through its governed writer."));
    }
    return fetch("/api/edit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (r) {
      return r.json().then(function (data) {
        if (!r.ok) throw new Error(data && data.error ? data.error : "request failed (" + r.status + ")");
        return data;
      });
    });
  }

  // Stage a draft from typed ops (forms/JSON), get back a diff to preview. No
  // commit happens here — the worker never auto-commits.
  function governance() { return CONFIG && CONFIG.authoring && CONFIG.authoring.governance; }
  function metadata(context) {
    if (!context || !context.reason || !Array.isArray(context.evidence) || !context.evidence.length) {
      throw new Error("A reason and evidence references are required for a governed change.");
    }
    return { id: context.id || crypto.randomUUID(), reason: context.reason, evidence: context.evidence };
  }
  function draft(ops, context) {
    return postEdit(Object.assign({ action: "draft", ops: ops }, governance() ? metadata(context) : {}));
  }

  // Commit a previously previewed draft — the explicit operator save. Carries the
  // per-file base SHA the draft returned (optimistic concurrency).
  function commit(files, message) {
    if (governance()) {
      if (!files || !files.proposalToken) return Promise.reject(new Error("A governed proposal is required."));
      return postEdit({ action: "commit", proposalToken: files.proposalToken });
    }
    return postEdit({ action: "commit", files: files, message: message });
  }

  // The embedded WYSIWYG edit-agent: rewrite/expand/summarize a selection. Returns
  // markdown to splice into the buffer — never commits.
  function bufferEdit(command, selection) {
    return postEdit({ action: "buffer", command: command, selection: selection });
  }

  // Conversational/agent edit (gated authoring_agent): an NL instruction the
  // editor agent turns into staged ops + a diff to confirm.
  function agentDraft(instruction, context) {
    return postEdit(Object.assign({ action: "draft", instruction: instruction }, governance() ? metadata(context) : {}));
  }

  // --- Form generation (schema-driven) ---------------------------------------
  // Build a form for one record type off its item schema. Each property becomes
  // an input keyed by type: enums and booleans become selects, string lists a
  // one-per-line textarea, nested objects and object lists a JSON textarea. The
  // point is generation FROM the schema so a new editable artifact needs zero
  // new UI.
  function fieldKind(p) {
    if (p.type === "integer" || p.type === "number") return "number";
    if (p.type === "boolean") return "boolean";
    if (p.type === "array") return p.items && p.items.type === "string" && !p.items.enum ? "list" : "json";
    if (p.type === "object" || p.$ref || Array.isArray(p.type)) return "json";
    return "text";
  }

  function buildForm(itemSchema, existing) {
    var form = document.createElement("form");
    form.className = "kb-editor-form";
    var props = (itemSchema && itemSchema.properties) || {};
    Object.keys(props).forEach(function (key) {
      if (key === "$comment") return;
      var p = props[key];
      var kind = fieldKind(p);
      var wrap = document.createElement("label");
      wrap.className = "kb-editor-field";
      wrap.textContent = key + ((itemSchema.required || []).indexOf(key) >= 0 ? " *" : "");
      var input;
      var value = existing ? existing[key] : undefined;
      if (p.enum || kind === "boolean") {
        input = document.createElement("select");
        [""].concat(p.enum || ["true", "false"]).forEach(function (opt) {
          var o = document.createElement("option");
          o.value = String(opt); o.textContent = opt === "" ? "(none)" : String(opt); input.appendChild(o);
        });
      } else if (kind === "text" && (key === "title" || key === "id" || p.format === "date" || /date$/.test(key))) {
        input = document.createElement("input");
      } else if (kind === "number") {
        input = document.createElement("input");
        input.type = "number";
      } else {
        input = document.createElement("textarea");
        input.rows = kind === "json" ? 6 : 3;
      }
      input.name = key;
      input.dataset.kind = kind;
      if (p.description) input.title = p.description;
      if (value != null) {
        input.value = kind === "list" ? value.join("\n") : kind === "json" ? JSON.stringify(value, null, 2) : String(value);
      }
      wrap.appendChild(input);
      var err = document.createElement("span");
      err.className = "kb-editor-error";
      err.dataset.field = key;
      wrap.appendChild(err);
      form.appendChild(wrap);
    });
    return form;
  }

  // Read a generated form back into {record, errors} (reversing buildForm).
  function readForm(form) {
    var fields = [];
    Array.prototype.forEach.call(form.elements, function (el) {
      if (el.name) fields.push({ name: el.name, kind: el.dataset ? el.dataset.kind : "text", value: el.value });
    });
    return recordFromFields(fields);
  }

  // Validate a staged op client-side. An update carries only changed fields, so
  // required-field checks apply to new records and to the panel's full record.
  function validateOp(op, itemSchema) {
    if (op.op === "add_record") return validateRecord(op.data, itemSchema);
    if (op.op === "update_record") return validateRecord(op.fields, Object.assign({}, itemSchema, { required: [] }));
    return [];
  }

  // --- Public surface ---------------------------------------------------------
  // window.__kbEditorApi is what the panel below (and tests) drive, so every
  // surface takes the same validated path. Everything routes through /api/edit.
  var api = {
    artifacts: function () { return ARTIFACTS; },
    features: function () { return FEATURES; },
    loadSchema: loadSchema,
    recordSchema: recordSchema,
    validateRecord: validateRecord,
    recordFromFields: recordFromFields,
    recordFromJson: recordFromJson,
    jsonErrorOffset: jsonErrorOffset,
    buildOp: buildOp,
    buildForm: buildForm,
    readForm: readForm,
    // Validate an op client-side, then stage it as a draft. Rejects (no draft,
    // no commit) when it is schema-invalid.
    stageOp: function (opObj, context) {
      var spec = ARTIFACTS[opObj.type];
      if (!spec) return Promise.reject(new Error("unknown artifact type: " + opObj.type));
      return loadSchema(spec.schema).then(function (schema) {
        var errs = validateOp(opObj, recordSchema(schema, spec.collection));
        if (errs.length) throw new Error("schema invalid: " + errs.join("; "));
        return draft([opObj], context);
      });
    },
    // The panel's path for an edited record from any surface: validate the whole
    // record, build its op, stage the draft.
    stageEdit: function (type, original, record, context) {
      var spec = ARTIFACTS[type];
      if (!spec) return Promise.reject(new Error("unknown artifact type: " + type));
      return loadSchema(spec.schema).then(function (schema) {
        var errs = validateRecord(record, recordSchema(schema, spec.collection));
        if (errs.length) throw new Error("schema invalid: " + errs.join("; "));
        var op = buildOp(type, original, record);
        if (op.op === "update_record" && !Object.keys(op.fields).length && !op.unset) throw new Error("No change to preview.");
        return api.stageOp(op, context);
      });
    },
    stageRecord: function (type, op, record, id, context) {
      var opObj = { op: op, type: type };
      if (op === "add_record") opObj.data = record;
      else if (op === "update_record") { opObj.id = id; opObj.fields = record; }
      else if (op === "set_status") { opObj.id = id; opObj.status = record; }
      return api.stageOp(opObj, context);
    },
    draft: draft,
    commit: commit,
    review: function (proposal, reason) {
      return postEdit({ action: "review", proposalToken: proposal.proposalToken, reason: reason });
    },
    bufferEdit: function (command, selection) {
      if (!FEATURES.authoring_wysiwyg && !FEATURES.authoring_wysiwyg_agent) {
        return Promise.reject(new Error("buffer edit-agent disabled"));
      }
      return bufferEdit(command, selection);
    },
    agentDraft: function (instruction, context) {
      if (!FEATURES.authoring_agent) return Promise.reject(new Error("conversational edit disabled"));
      return agentDraft(instruction, context);
    },
  };

  // --- Panel ------------------------------------------------------------------
  // Pick a type and a record (or a new one), edit it as a form, as JSON or as a
  // prose buffer, preview the diff the Worker drafts, then save. Save is enabled
  // only for the draft currently previewed; any further edit clears it. A stale
  // save (the record changed upstream) offers a reload of the records.
  var STYLE = [
    "#kb-editor-launch{position:fixed;left:16px;bottom:16px;z-index:9998;padding:8px 14px;border-radius:6px;border:1px solid var(--kb-border,#8884);background:var(--kb-surface,#fff);color:var(--kb-text,#111);cursor:pointer}",
    "#kb-editor-panel{position:fixed;inset:5vh 5vw;z-index:9999;display:flex;flex-direction:column;gap:8px;padding:16px;overflow:auto;border-radius:8px;border:1px solid var(--kb-border,#8884);background:var(--kb-bg,#fff);color:var(--kb-text,#111);box-shadow:0 8px 32px #0005}",
    "#kb-editor-panel[hidden]{display:none}",
    ".kb-editor-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}",
    ".kb-editor-form{display:grid;gap:8px}",
    ".kb-editor-field{display:grid;gap:2px;font-size:.9em}",
    "#kb-editor-panel textarea,#kb-editor-panel input,#kb-editor-panel select{font:inherit;padding:4px;border:1px solid var(--kb-border,#8884);border-radius:4px;background:var(--kb-surface,#fff);color:inherit}",
    "#kb-editor-panel textarea.kb-editor-code{font-family:ui-monospace,monospace;min-height:40vh}",
    ".kb-editor-error,.kb-editor-errors{color:#c0392b;font-size:.85em;white-space:pre-wrap}",
    ".kb-editor-diff{font-family:ui-monospace,monospace;font-size:.85em;white-space:pre-wrap;border:1px solid var(--kb-border,#8884);padding:8px;border-radius:4px}",
    "#kb-editor-panel button[aria-pressed=true]{font-weight:bold;text-decoration:underline}",
  ].join("\n");

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text != null) node.textContent = text;
    return node;
  }

  function diffLines(before, after) {
    var a = String(before || "").split("\n");
    var b = String(after || "").split("\n");
    var i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    var ja = a.length, jb = b.length;
    while (ja > i && jb > i && a[ja - 1] === b[jb - 1]) { ja--; jb--; }
    return a.slice(i, ja).map(function (l) { return "- " + l; }).concat(b.slice(i, jb).map(function (l) { return "+ " + l; }));
  }

  function openPanel() {
    var existing = document.getElementById("kb-editor-panel");
    if (existing) { existing.hidden = false; return; }
    var panel = el("div", { id: "kb-editor-panel", role: "dialog", "aria-label": "Edit records" });
    var close = el("button", { type: "button" }, "Close");
    close.addEventListener("click", function () { panel.hidden = true; });
    panel.appendChild(el("div", { class: "kb-editor-row" })).appendChild(close);
    document.body.appendChild(panel);

    if (authority()) {
      panel.appendChild(el("p", {}, "Records in this brain are held by its declared authority. Propose changes through the authority's governed writer; this editor does not write them."));
      var link = el("a", { href: "/knowledge-workbench/" }, "Open the knowledge workbench");
      panel.appendChild(link);
      return;
    }

    var state = { type: null, spec: null, itemSchema: null, records: [], original: null, record: {}, mode: "form", draft: null };
    var typeSel = el("select", { "aria-label": "Record type" });
    var recSel = el("select", { "aria-label": "Record" });
    var modes = el("div", { class: "kb-editor-row", role: "tablist" });
    var body = el("div", {});
    var errors = el("div", { class: "kb-editor-errors", "aria-live": "polite" });
    var meta = el("div", { class: "kb-editor-row" });
    var message = el("input", { placeholder: "Commit message", "aria-label": "Commit message" });
    var reason = el("input", { placeholder: "Reason (required)", "aria-label": "Reason" });
    var evidence = el("input", { placeholder: "Evidence references, comma-separated", "aria-label": "Evidence" });
    var preview = el("button", { type: "button" }, "Preview");
    var save = el("button", { type: "button" }, "Save");
    var reload = el("button", { type: "button", hidden: "" }, "Reload records");
    var diff = el("pre", { class: "kb-editor-diff", hidden: "" });
    var status = el("p", { "aria-live": "polite" });

    var header = el("div", { class: "kb-editor-row" });
    header.appendChild(typeSel);
    header.appendChild(recSel);
    panel.appendChild(header);
    panel.appendChild(modes);
    panel.appendChild(body);
    panel.appendChild(errors);
    meta.appendChild(message);
    if (governance()) { meta.appendChild(reason); meta.appendChild(evidence); }
    panel.appendChild(meta);
    var actions = el("div", { class: "kb-editor-row" });
    [preview, save, reload].forEach(function (b) { actions.appendChild(b); });
    panel.appendChild(actions);
    panel.appendChild(diff);
    panel.appendChild(status);

    Object.keys(ARTIFACTS).forEach(function (type) {
      typeSel.appendChild(el("option", { value: type }, ARTIFACTS[type].title));
    });

    function invalidate() {
      state.draft = null;
      save.disabled = true;
      diff.hidden = true;
    }

    function showErrors(list) {
      errors.textContent = list.join("\n");
      preview.disabled = list.length > 0;
      if (list.length) save.disabled = true;
    }

    // The current record from the active surface, plus its full-record errors.
    function current() {
      if (state.mode === "json") {
        var parsed = recordFromJson(body.querySelector("textarea").value);
        if (!parsed.record) return parsed;
        return { record: parsed.record, errors: validateRecord(parsed.record, state.itemSchema) };
      }
      if (state.mode === "form") {
        // The form shows only schema properties; carry any other field through
        // so it is not read as cleared.
        var read = readForm(body.querySelector("form"));
        var props = (state.itemSchema && state.itemSchema.properties) || {};
        var rec = {};
        Object.keys(state.record).forEach(function (k) { if (!props[k]) rec[k] = state.record[k]; });
        Object.assign(rec, read.record);
        return { record: rec, errors: read.errors.concat(validateRecord(rec, state.itemSchema)) };
      }
      return { record: state.record, errors: validateRecord(state.record, state.itemSchema) };
    }

    function onEdit() {
      invalidate();
      var c = current();
      if (c.record) state.record = c.record;
      Array.prototype.forEach.call(body.querySelectorAll(".kb-editor-error"), function (span) {
        var key = span.dataset.field;
        span.textContent = c.errors.filter(function (e) { return e.indexOf(key) >= 0; }).join("; ");
      });
      showErrors(c.errors);
    }

    function render() {
      body.textContent = "";
      invalidate();
      if (state.mode === "form") {
        var form = buildForm(state.itemSchema, state.record);
        form.addEventListener("input", onEdit);
        form.addEventListener("change", onEdit);
        body.appendChild(form);
      } else if (state.mode === "json") {
        var code = el("textarea", { class: "kb-editor-code", spellcheck: "false", "aria-label": "Record JSON" });
        code.value = JSON.stringify(state.record, null, 2);
        code.addEventListener("input", onEdit);
        var fmt = el("button", { type: "button" }, "Format");
        fmt.addEventListener("click", function () {
          var parsed = recordFromJson(code.value);
          if (parsed.record) code.value = JSON.stringify(parsed.record, null, 2);
          onEdit();
        });
        body.appendChild(fmt);
        body.appendChild(code);
      } else {
        renderProse();
      }
      onEdit();
    }

    // Prose: a markdown buffer for one string field. Agent commands rewrite the
    // selection inside the buffer only; nothing reaches the record until "Apply
    // to record", and nothing is committed until Preview and Save.
    function renderProse() {
      var props = (state.itemSchema && state.itemSchema.properties) || {};
      var textFields = Object.keys(props).filter(function (k) { return props[k].type === "string" && !props[k].enum; });
      var fieldSel = el("select", { "aria-label": "Prose field" });
      textFields.forEach(function (k) { fieldSel.appendChild(el("option", { value: k }, k)); });
      var buffer = el("textarea", { class: "kb-editor-code", "aria-label": "Prose buffer" });
      var row = el("div", { class: "kb-editor-row" });
      row.appendChild(fieldSel);
      function load() { buffer.value = state.record[fieldSel.value] || ""; }
      fieldSel.addEventListener("change", load);
      if (FEATURES.authoring_wysiwyg || FEATURES.authoring_wysiwyg_agent) {
        ["rewrite", "expand", "summarize"].forEach(function (command) {
          var b = el("button", { type: "button" }, command);
          b.addEventListener("click", function () {
            var start = buffer.selectionStart, end = buffer.selectionEnd;
            var selection = start < end ? buffer.value.slice(start, end) : buffer.value;
            status.textContent = "Asking the edit agent...";
            api.bufferEdit(command, selection).then(function (out) {
              buffer.value = start < end ? buffer.value.slice(0, start) + out.markdown + buffer.value.slice(end) : out.markdown;
              status.textContent = "Buffer updated. Apply it to the record, then preview.";
            }).catch(function (e) { status.textContent = e.message; });
          });
          row.appendChild(b);
        });
      }
      var apply = el("button", { type: "button" }, "Apply to record");
      apply.addEventListener("click", function () {
        var next = Object.assign({}, state.record);
        if (buffer.value.trim() === "") delete next[fieldSel.value];
        else next[fieldSel.value] = buffer.value;
        state.record = next;
        onEdit();
      });
      row.appendChild(apply);
      body.appendChild(row);
      body.appendChild(buffer);
      load();
    }

    [["form", "Form"], ["json", "JSON"], ["prose", "Prose"]].forEach(function (m) {
      var b = el("button", { type: "button", role: "tab" }, m[1]);
      b.addEventListener("click", function () {
        var c = current();
        if (!c.record) { showErrors(c.errors.concat(["Fix the current view before switching."])); return; }
        state.record = c.record;
        state.mode = m[0];
        Array.prototype.forEach.call(modes.children, function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        render();
      });
      b.setAttribute("aria-pressed", String(m[0] === state.mode));
      modes.appendChild(b);
    });

    function selectRecord() {
      var idx = recSel.value;
      state.original = idx === "new" ? null : state.records[Number(idx)];
      state.record = state.original ? JSON.parse(JSON.stringify(state.original)) : {};
      render();
    }

    function loadRecords() {
      reload.hidden = true;
      status.textContent = "";
      return fetch("/" + state.spec.path, { cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : {}; })
        .then(function (doc) {
          state.records = Array.isArray(doc[state.spec.collection]) ? doc[state.spec.collection] : [];
          recSel.textContent = "";
          recSel.appendChild(el("option", { value: "new" }, "New record"));
          state.records.forEach(function (rec, i) {
            var id = recordId(rec);
            if (id != null) recSel.appendChild(el("option", { value: String(i) }, id));
          });
          selectRecord();
        });
    }

    function selectType() {
      state.type = typeSel.value;
      state.spec = ARTIFACTS[state.type];
      if (!state.spec) return;
      loadSchema(state.spec.schema).then(function (schema) {
        state.itemSchema = recordSchema(schema, state.spec.collection);
        return loadRecords();
      });
    }

    function context() {
      if (!governance()) return undefined;
      return { reason: reason.value.trim(), evidence: evidence.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean) };
    }

    preview.addEventListener("click", function () {
      var c = current();
      if (c.errors.length) { showErrors(c.errors); return; }
      status.textContent = "Drafting...";
      api.stageEdit(state.type, state.original, c.record, context()).then(function (d) {
        state.draft = d;
        diff.textContent = (d.files || []).map(function (f) { return f.path + "\n" + diffLines(f.before, f.after).join("\n"); }).join("\n\n");
        diff.hidden = false;
        save.disabled = false;
        status.textContent = "Review the change, then save.";
      }).catch(function (e) { status.textContent = e.message; });
    });

    save.addEventListener("click", function () {
      if (!state.draft) return;
      save.disabled = true;
      status.textContent = "Saving...";
      var target = governance() ? state.draft : state.draft.files;
      commit(target, message.value.trim() || undefined).then(function (r) {
        state.draft = null;
        status.textContent = r.pullRequest ? "" : "Saved.";
        if (r.pullRequest) {
          status.appendChild(el("a", { href: r.pullRequest.url }, "Pull request #" + r.pullRequest.number + " opened for review"));
        }
      }).catch(function (e) {
        status.textContent = e.message;
        if (/changed upstream|stale|propose again/.test(e.message)) reload.hidden = false;
      });
    });

    reload.addEventListener("click", loadRecords);
    typeSel.addEventListener("change", selectType);
    recSel.addEventListener("change", selectRecord);
    selectType();
  }

  function mountLauncher() {
    var style = document.createElement("style");
    style.textContent = STYLE;
    (document.head || document.body).appendChild(style);
    var btn = document.createElement("button");
    btn.id = "kb-editor-launch";
    btn.type = "button";
    btn.textContent = "Edit";
    btn.setAttribute("aria-label", "Open the authoring editor");
    btn.addEventListener("click", openPanel);
    document.body.appendChild(btn);
  }

  loadConfig().then(function (cfg) {
    CONFIG = cfg || {};
    FEATURES = CONFIG.features || {};
    // Defense in depth: the worker only injects this file when features.authoring
    // is on, but bail anyway if the served config disagrees.
    if (!FEATURES.authoring) return;
    return loadArtifacts().then(function (artifacts) {
      ARTIFACTS = artifacts;
      window.__kbEditorApi = api;
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", mountLauncher);
      } else {
        mountLauncher();
      }
    });
  });
})();
